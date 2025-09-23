<h1 align="center">BugScribe</h1>

<p align="center">
    <img 
        src="./public/logo_image_text.png" 
        alt="BugScribe Logo"
        width="500"
        height="300"
        />
</p></br>

BugScribe is a Node.js-based bug reporting and suggestion management system. It provides a simple backend for collecting, storing, and managing bug reports, suggestions, and related data for your applications or services.

## Features
- Collects bug reports and suggestions from users
- Stores data in JSON files for easy access and migration
- Admin credential management
- Data migration utilities
- Logging for bot attempts, IP history, and spam
- File uploads support

## Project Structure
```
admin-credentials.json         # Admin credentials storage
create-admin.js                # Script to create admin users
index.html                     # Main HTML page
LICENSE                        # Project license
migrate-data.js                # Data migration script
nodemon.json                   # Nodemon configuration
package.json                   # Project metadata and dependencies
server.js                      # Main server file
data/                          # JSON data storage
  ├─ bot-attempts.json
  ├─ bug-reports.json
  ├─ ip-history.json
  ├─ spam-log.json
  └─ suggestions-reports.json
public/                        # Public assets
uploads/                       # Uploaded files
```

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v14 or higher recommended)
- npm (comes with Node.js)

### Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/LadishDev/BugScribe.git
   cd BugScribe
   ```
2. Install dependencies:
   ```sh
   npm install
   ```

### Running the Server
Start the server with:
```sh
npx run dev
```

### Creating an Admin User
Run the following script to create an admin user:
```sh
node create-admin.js
```
Follow the prompts to set up admin credentials.

### Migrating Data
To migrate data, use:
```sh
node migrate-data.js
```

## Data Files
- All user reports, suggestions, and logs are stored in the `data/` directory as JSON files.
- Uploaded files are stored in the `uploads/` directory.

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE)

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## Contact
For questions or support, please open an issue on the [GitHub repository](https://github.com/LadishDev/BugScribe).
