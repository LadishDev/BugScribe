const bcrypt = require('bcryptjs');
const fs = require('fs-extra');
const path = require('path');

// Script to create secure admin credentials (now located at lib/tools/create-admin.js)
async function createAdminUser() {
  const username = process.argv[2] || 'admin';
  const password = process.argv[3];
  
  if (!password) {
    console.log('Usage: node lib/tools/create-admin.js <username> <password>');
    console.log('Example: node lib/tools/create-admin.js admin mySecurePassword123!');
    process.exit(1);
  }

  try {
    // Hash the password with salt rounds of 12 (very secure)
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
  // Load existing credentials or create new structure in data/
  const adminFile = path.join(__dirname, '..', '..', 'data', 'admin-credentials.json');
    let adminCredentials;
    
    if (await fs.pathExists(adminFile)) {
      adminCredentials = await fs.readJson(adminFile);
      
      // Check if user already exists
      const existingUserIndex = adminCredentials.users.findIndex(u => u.username === username);
      if (existingUserIndex !== -1) {
        console.log(`⚠️  User '${username}' already exists. Updating password...`);
        adminCredentials.users[existingUserIndex].passwordHash = hashedPassword;
        adminCredentials.users[existingUserIndex].updatedAt = new Date().toISOString();
      } else {
        // Add new user
        adminCredentials.users.push({
          username: username,
          passwordHash: hashedPassword,
          createdAt: new Date().toISOString(),
          lastLogin: null
        });
      }
    } else {
      // Create new credentials file
      adminCredentials = {
        version: "1.0",
        createdAt: new Date().toISOString(),
        users: [{
          username: username,
          passwordHash: hashedPassword,
          createdAt: new Date().toISOString(),
          lastLogin: null
        }]
      };
    }
    
    // Save credentials
    await fs.writeJson(adminFile, adminCredentials, { spaces: 2 });
    
    console.log('✅ Admin user created/updated successfully!');
    console.log(`Username: ${username}`);
    console.log('Password: [HIDDEN FOR SECURITY]');
    console.log(`Total admin users: ${adminCredentials.users.length}`);
    console.log(`Credentials saved to: ${adminFile}`);
    console.log('\n⚠️  IMPORTANT SECURITY NOTES:');
    console.log('1. Delete this script after use');
  console.log('2. Never commit data/admin-credentials.json to version control');
    console.log('3. Set proper file permissions on the credentials file');
    console.log('4. Use strong, unique passwords');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error.message);
    process.exit(1);
  }
}

if (require.main === module) createAdminUser();
