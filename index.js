require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');
const SecureTokenStorage = require('./tokenStorage');

const app = express();
const PORT = process.env.PORT;

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
    version: '2.0.0',
    status: 'running',
    endpoints: {
      auth: '/auth/login',
      callback: '/auth/callback',
      creator_info: '/creator-info',
      user_info: '/user/info',
      video_upload: 'POST /video/upload (Pull from URL)',
      video_status: '/video/status?publish_id=YOUR_PUBLISH_ID',
      health: '/health',
      shutdown: 'POST /shutdown'
    },
    note: 'Now using Pull from URL method for video uploads (supports up to 4GB)'
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
      <h1>✅ Login Successful!</h1>
      <p>Tokens acquired and stored securely.</p>
      <h2>Available Endpoints:</h2>
      <ul>
        <li><a href="/creator-info">Creator Info</a> - Get your TikTok profile info</li>
        <li><a href="/user/info?fields=open_id,union_id,avatar_url,display_name,bio_description">User Info</a> - Get your TikTok user info</li>
        <li><a href="/health">Health Check</a> - Server status</li>
      </ul>
      <h3>API Usage (Pull from URL method):</h3>
      <pre>
POST /video/upload
Content-Type: application/json

{
  "video_url": "https://your-minio-url.com/bucket/video.mp4",
  "post_info": {
    "title": "Your video title with #hashtags",
    "privacy_level": "PUBLIC_TO_EVERYONE",
    "disable_comment": false,
    "disable_duet": false,
    "disable_stitch": false,
    "video_cover_timestamp_ms": 1000
  }
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

// 6. Video upload API - INBOX METHOD (No approval needed)
app.post('/video/upload', async (req, res) => {
  try {
    const access_token = await getValidAccessToken();
    const { video_url, post_info } = req.body;

    if (!video_url) {
      return res.status(400).json({ error: 'video_url is required' });
    }

    console.log('📹 Downloading video from MinIO...');
    
    // Download video from MinIO
    const videoResponse = await axios.get(video_url, {
      responseType: 'arraybuffer',
      maxContentLength: 500 * 1024 * 1024 // 500MB limit
    });
    
    const videoBuffer = Buffer.from(videoResponse.data);
    const videoSize = videoBuffer.length;
    
    console.log(`✅ Downloaded: ${(videoSize / 1024 / 1024).toFixed(2)} MB`);

    // Initialize inbox upload
    const initResponse = await axios.post(
      'https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',
      {
        source_info: {
          source: 'FILE_UPLOAD',
          video_size: videoSize,
          chunk_size: videoSize,
          total_chunk_count: 1
        }
      },
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json; charset=UTF-8'
        }
      }
    );

    if (initResponse.data.error && initResponse.data.error.code !== 'ok') {
      throw new Error(`TikTok API Error: ${initResponse.data.error.message}`);
    }

    const { publish_id, upload_url } = initResponse.data.data;
    
    console.log('📤 Uploading to TikTok inbox...');

    // Upload video
    await axios.put(upload_url, videoBuffer, {
      headers: {
        'Content-Range': `bytes 0-${videoSize - 1}/${videoSize}`,
        'Content-Type': 'video/mp4',
        'Content-Length': videoSize
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    console.log('✅ Upload complete!');

    res.json({
      success: true,
      message: 'Video uploaded to TikTok inbox successfully',
      data: {
        publish_id: publish_id,
        video_size_mb: (videoSize / 1024 / 1024).toFixed(2),
        note: 'Video is in your TikTok inbox. Open TikTok app to complete posting.'
      }
    });

  } catch (err) {
    console.error('❌ Upload error:', err.response?.data || err.message);
    
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

// 8. Shutdown endpoint - gracefully shut down the server
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


// Add your own API endpoints here

app.listen(PORT, () => {
  console.log(`🚀 TikTok OAuth2 Server running at http://localhost:${PORT}`);
  console.log(`📖 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Perform OAuth flow: http://localhost:${PORT}/auth/login`);
  console.log(`📹 Video upload method: Pull from URL (supports up to 4GB)`);
  console.log(`🛑 Shutdown: POST http://localhost:${PORT}/shutdown`);
});
