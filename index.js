require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');
const SecureTokenStorage = require('./tokenStorage');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT;

// Configure multer for file uploads
const upload = multer({ 
  dest: '/tmp/uploads/',
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB limit
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize secure storage with encryption key from environment
const tokenStorage = new SecureTokenStorage(
     process.env.ENCRYPTION_KEY,
     './data/tokens.encrypted.json'
   );

// Store code verifier for PKCE flow
let codeVerifier = null;

// Generate random string for code verifier (TikTok's official method)
function generateRandomString(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

// Generate PKCE code verifier and challenge (TikTok's official method)
function generatePKCE() {
  // Generate random code verifier (43-128 characters as per TikTok docs)
  const verifier = generateRandomString(64); // Using 64 characters for good entropy
  
  // Generate code challenge using SHA256 with hex encoding (TikTok's method)
  const challenge = crypto.createHash('sha256').update(verifier).digest('hex');
  
  return { verifier, challenge };
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root endpoint with basic info
app.get('/', (req, res) => {
  res.json({
    name: 'TikTok OAuth2 Server',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      auth: '/auth/login',
      callback: '/auth/callback',
      creator_info: '/creator-info',
      user_info: '/user/info',
      video_direct_post: '/video/direct-post',
      video_upload: '/video/upload',
      video_status: '/video/status?publish_id=YOUR_PUBLISH_ID',
      health: '/health',
      shutdown: 'POST /shutdown',
      force_shutdown: 'POST /shutdown/force',
      nuclear_shutdown: 'POST /shutdown/nuclear'
    }
  });
});

// 1. Redirect user to TikTok auth page with PKCE
app.get('/auth/login', (req, res) => {
  // Generate PKCE code verifier and challenge
  const pkce = generatePKCE();
  codeVerifier = pkce.verifier; // Store for later use in callback

  const params = {
    client_key: process.env.TIKTOK_CLIENT_KEY,
    redirect_uri: process.env.TIKTOK_REDIRECT_URI,
    response_type: 'code',
    scope: 'user.info.basic,user.info.profile,user.info.stats,video.publish,video.upload',
    state: 'secureRandomState123', // optional
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256'
  };

  const authUrl = `https://www.tiktok.com/v2/auth/authorize/?${qs.stringify(params)}`;
  res.redirect(authUrl);
});

// 2. Callback endpoint to handle TikTok redirect with PKCE
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');
  
  if (!codeVerifier) return res.status(400).send('No code verifier found');

  //console.log('Callback received - Code:', code);
  //console.log('Stored code verifier:', codeVerifier);

  try {
    const requestData = new URLSearchParams({
      client_key: process.env.TIKTOK_CLIENT_KEY,
      client_secret: process.env.TIKTOK_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.TIKTOK_REDIRECT_URI,
      code_verifier: codeVerifier
    });

    const tokenRes = await axios.post('https://open.tiktokapis.com/v2/oauth/token/', requestData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      }
    });
    
    if (tokenRes.data.error) {
      return res.status(400).send(`Error: ${tokenRes.data.error}, Description: ${tokenRes.data.error_description}`);
    }
    if (!tokenRes.data.access_token) {
      return res.status(400).send('Access token not received');
    }

    const { access_token, refresh_token, expires_in } = tokenRes.data;

    // Save tokens securely
    tokenStorage.saveTokens({
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // Clear code verifier after successful token exchange
    codeVerifier = null;

    res.send(`
      <h1>âœ… Login Successful!</h1>
      <p>Tokens acquired and stored securely.</p>
      <h2>Available Endpoints:</h2>
      <ul>
        <li><a href="/creator-info">Creator Info</a> - Get your TikTok profile info</li>
        <li><a href="/user/info?fields=open_id,union_id,avatar_url,display_name,bio_description">User Info</a> - Get your TikTok user info</li>
        <li><a href="/health">Health Check</a> - Server status</li>
      </ul>
      <h3>API Usage:</h3>
      <pre>
POST /video/direct-post
{
  "file_path": "/path/to/video.mp4",
  "title": "Your video title"
}

GET /video/status?publish_id=YOUR_PUBLISH_ID
      </pre>
    `);
  } catch (err) {
    console.error('Token exchange error:', err.response?.data || err.message);
    res.status(500).send('Token exchange failed');
  }
});

// 3. Auto-refresh access token if expired
async function getValidAccessToken() {
  const tokens = tokenStorage.loadTokens();
  if (!tokens) {
    throw new Error(`No tokens available. Please complete OAuth flow first. Visit http://localhost:${PORT}/auth/login`);
  }

  if (Date.now() < tokens.expires_at - 60 * 1000) {
    console.log('✅ Using existing access token');
    return tokens.access_token;
  }

  console.log('🔄 Refreshing TikTok access token...');
  
  try {
    // ⭐ FIX: Use URLSearchParams instead of JSON (same format as auth callback)
    const requestData = new URLSearchParams({
      client_key: process.env.TIKTOK_CLIENT_KEY,
      client_secret: process.env.TIKTOK_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
    });

    const refreshRes = await axios.post(
      'https://open.tiktokapis.com/v2/oauth/token/', 
      requestData,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        }
      }
    );

    if (refreshRes.data.error) {
      console.error('❌ Token refresh failed:', refreshRes.data.error);
      throw new Error(`Token refresh failed: ${refreshRes.data.error_description}`);
    }

    const { access_token, refresh_token, expires_in } = refreshRes.data;

    // Save new tokens
    tokenStorage.saveTokens({
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    console.log('✅ Token refreshed successfully');
    return access_token;
  } catch (error) {
    console.error('❌ Token refresh error:', error.response?.data || error.message);
    throw new Error(`Token refresh failed. Please re-authenticate at http://localhost:${PORT}/auth/login`);
  }
}

// 4. Test by calling TikTok API creator_info with access token
app.get('/creator-info', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();

    const profile = await axios.post('https://open.tiktokapis.com/v2/post/publish/creator_info/query/', {}, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
    });

    res.json(profile.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send('API call failed');
  }
});

// 5. User info API - accepts fields from client and forwards to TikTok
app.get('/user/info', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { fields } = req.query;

    if (!fields) {
      return res.status(400).json({ 
        error: 'fields query parameter is required',
        example: 'GET /user/info?fields=open_id,union_id,avatar_url'
      });
    }

    const userInfoResponse = await axios.get(`https://open.tiktokapis.com/v2/user/info/?fields=${fields}`, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
      }
    });

    res.json(userInfoResponse.data);
  } catch (err) {
    console.error('User info error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'User info request failed',
      details: err.response?.data || err.message
    });
  }
});

// 6. Simple video upload API - takes file path and title
app.post('/video/direct-post', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { file_path, title } = req.body;

    if (!file_path) {
      return res.status(400).json({ error: 'file_path is required' });
    }

    if (!title) {
      return res.status(400).json({ error: 'title is required' });
    }

    // Check if file exists
    if (!fs.existsSync(file_path)) {
      return res.status(400).json({ error: 'File not found at specified path' });
    }

    // Get file stats
    const stats = fs.statSync(file_path);
    const fileSize = stats.size;
    const chunkSize = (fileSize < 10 * 1024 * 1024) ? fileSize : 10 * 1024 * 1024; // 10MB chunks
    const totalChunkCount = Math.ceil(fileSize / chunkSize);

    // Step 1: Initialize video upload
    console.log('Initializing video upload...');
    const initResponse = await axios.post('https://open.tiktokapis.com/v2/post/publish/video/init/', {
      post_info: {
        title: title,
        privacy_level: 'PUBLIC_TO_EVERYONE',
        disable_duet: false,
        disable_comment: false,
        disable_stitch: false,
        video_cover_timestamp_ms: 1000
      },
      source_info: {
        source: 'FILE_UPLOAD',
        video_size: fileSize,
        chunk_size: chunkSize,
        total_chunk_count: totalChunkCount
      }
    }, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      }
    });

    if (initResponse.data.error && initResponse.data.error.code !== 'ok') {
      throw new Error(`TikTok API Error: ${initResponse.data.error.message}`);
    }

    const { publish_id, upload_url } = initResponse.data.data;
    console.log('Upload initialized:', { publish_id, upload_url });

    // Step 2: Upload video file to TikTok's designated URL
    console.log('Uploading video file...');
    const videoBuffer = fs.readFileSync(file_path);
    
    const uploadResponse = await axios.put(upload_url, videoBuffer, {
      headers: {
        'Content-Range': `bytes 0-${fileSize - 1}/${fileSize}`,
        'Content-Type': 'video/mp4',
        'Content-Length': fileSize
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    console.log('Video upload requested. Check status at http://localhost:${PORT}/video/status?publish_id=${publish_id}');

    // Return success response with publish_id
    res.json({
      success: true,
      message: 'Video upload requested successfully',
      data: {
        publish_id: publish_id,
        status_url: `http://localhost:${PORT}/video/status?publish_id=${publish_id}`,
        file_info: {
          path: file_path,
          size: fileSize,
          size_mb: (fileSize / 1024 / 1024).toFixed(2)
        }
      }
    });

  } catch (err) {
    console.error('Video upload error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'Video upload failed',
      details: err.response?.data || err.message
    });
  }
});

// 7. Check video upload status using query parameters
app.get('/video/status', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { publish_id } = req.query;

    if (!publish_id) {
      return res.status(400).json({ error: 'publish_id query parameter is required' });
    }

    const statusResponse = await axios.post('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      publish_id: publish_id
    }, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      }
    });

    res.json(statusResponse.data);

  } catch (err) {
    console.error('Status check error:', err.response?.data || err.message);
    res.status(500).json({
      error: 'Status check failed',
      details: err.response?.data || err.message
    });
  }
});

// 8. Video upload API - NOW ACCEPTS FILE UPLOADS FROM N8N
app.post('/video/upload', upload.single('video'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No video file uploaded' });
    }

    const videoPath = req.file.path;
    const videoSize = req.file.size;
    
    console.log('📹 Video received from N8N:', {
      filename: req.file.originalname,
      size: `${(videoSize / 1024 / 1024).toFixed(2)} MB`,
      path: videoPath
    });

    const access_token = await getValidAccessToken();

    // Get file stats
    const chunkSize = (videoSize < 10 * 1024 * 1024) ? videoSize : 10 * 1024 * 1024; // 10MB chunks
    const totalChunkCount = Math.ceil(videoSize / chunkSize);

    console.log('Starting video upload process...');
    console.log('File info:', { size: videoSize, size_mb: (videoSize / 1024 / 1024).toFixed(2) });

    // Step 1: Initialize video upload
    console.log('Step 1: Initializing video upload...');
    const initResponse = await axios.post('https://open.tiktokapis.com/v2/post/publish/inbox/video/init/', {
      source_info: {
        source: 'FILE_UPLOAD',
        video_size: videoSize,
        chunk_size: chunkSize,
        total_chunk_count: totalChunkCount
      }
    }, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      }
    });

    if (initResponse.data.error && initResponse.data.error.code !== 'ok') {
      // Clean up temp file before throwing error
      fs.unlinkSync(videoPath);
      throw new Error(`TikTok API Error: ${initResponse.data.error.message}`);
    }

    const { publish_id, upload_url } = initResponse.data.data;
    console.log('Upload initialized:', { publish_id, upload_url });

    // Step 2: Upload video file to TikTok's designated URL
    console.log('Step 2: Uploading video file to TikTok...');
    
    const videoBuffer = fs.readFileSync(videoPath);
    console.log('Video buffer loaded, size:', videoBuffer.length, 'bytes');
    
    const uploadResponse = await axios.put(upload_url, videoBuffer, {
      headers: {
        'Content-Range': `bytes 0-${videoSize - 1}/${videoSize}`,
        'Content-Type': 'video/mp4',
        'Content-Length': videoSize
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    console.log('Upload response status:', uploadResponse.status);
    console.log('✅ Video uploaded to TikTok inbox successfully');

    // Clean up temporary file
    fs.unlinkSync(videoPath);
    console.log('🗑️ Temporary file cleaned up');

    // Return success response with publish_id
    res.json({
      success: true,
      message: 'Video uploaded to TikTok inbox successfully. User must complete editing flow in TikTok app.',
      data: {
        publish_id: publish_id,
        file_info: {
          original_name: req.file.originalname,
          size: videoSize,
          size_mb: (videoSize / 1024 / 1024).toFixed(2)
        },
        note: 'Video is now in TikTok inbox. User must click on inbox notifications to continue the editing flow in TikTok and complete the post.'
      }
    });

  } catch (err) {
    console.error('❌ Video upload error:', err.response?.data || err.message);
    
    // Clean up temp file on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
      console.log('🗑️ Temporary file cleaned up after error');
    }
    
    res.status(500).json({
      error: 'Video upload failed',
      details: err.response?.data || err.message
    });
  }
});

// 9. Shutdown endpoint - gracefully shut down the server
app.post('/shutdown', (req, res) => {
  console.log('🛑 Shutdown request received...');
  
  // Send immediate response to client
  res.json({
    success: true,
    message: 'Server shutdown initiated',
    timestamp: new Date().toISOString()
  });

  // Gracefully shut down the server after a short delay
  setTimeout(() => {
    console.log('🔄 Shutting down server...');
    
    // Try to kill the parent process (nodemon, pm2, etc.) if possible
    const parentPid = process.ppid;
    if (parentPid && parentPid !== 1) {
      try {
        console.log(`🔄 Attempting to kill parent process (PID: ${parentPid})...`);
        process.kill(parentPid, 'SIGTERM');
        
        // Give parent process a moment to shut down gracefully
        setTimeout(() => {
          console.log('🔄 Exiting current process...');
          process.exit(0);
        }, 2000);
      } catch (error) {
        console.log('⚠️ Could not kill parent process, exiting current process only...');
        process.exit(0);
      }
    } else {
      console.log('🔄 Exiting current process...');
      process.exit(0);
    }
  }, 1000); // 1 second delay to ensure response is sent
});


// add your own api endpoint here

app.listen(PORT, () => {
  console.log(`🚀 TikTok OAuth2 Server running at http://localhost:${PORT}`);
  console.log(`📖 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Perform OAuth flow: http://localhost:${PORT}/auth/login`);
  console.log(`🛑 Shutdown: POST http://localhost:${PORT}/shutdown`);
});
