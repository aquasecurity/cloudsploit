/**
 * Google Cloud Function entry point for running CloudSploit scans via HTTP.
 * This file should be placed in the root of the CloudSploit repository.
 *
 * This function adapts the CloudSploit CLI tool to run in a serverless environment.
 * It is triggered by an HTTP POST request and expects a JSON body with the following structure:
 * {
 * "serviceAccount": { ... a GCP service account key JSON object ... },
 * "plugins": ["gce", "gcs"], // Optional: array of plugins to run. If omitted, all are run.
 * "compliance": "pci" // Optional: specify a compliance standard.
 * }
 */
const cloudsploit = require('./lib/cloudsploit');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

// --- Promise Wrapper for CloudSploit's Callback-based `run` function ---
// This is the key to handling the asynchronous nature of CloudSploit without
// refactoring the entire library. We wrap the main `run` function in a Promise,
// which allows us to use `async/await` in our handler to wait for completion.
const runCloudSploit = (config) => {
    return new Promise((resolve, reject) => {
        cloudsploit.run(config, (err, results) => {
            if (err) {
                console.error('Error from CloudSploit engine:', err);
                return reject(new Error('CloudSploit engine failed to run.'));
            }
            resolve(results);
        });
    });
};


/**
 * Main HTTP Cloud Function handler.
 * @param {object} req - The Express-like request object.
 * @param {object} res - The Express-like response object.
 */
exports.cloudsploitScanner = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    // --- Input Validation ---
    if (!req.body || !req.body.serviceAccount) {
        return res.status(400).send('Bad Request: "serviceAccount" key missing from request body.');
    }

    if (typeof req.body.serviceAccount !== 'object' || !req.body.serviceAccount.project_id) {
         return res.status(400).send('Bad Request: "serviceAccount" must be a valid GCP key object.');
    }

    let tempKeyPath = '';

    try {
        // --- Dynamic Configuration ---
        // We create the configuration object programmatically from the request body.

        // Cloud Functions have a writable /tmp directory. We write the service
        // account key here temporarily so CloudSploit's GCP collector can read it.
        tempKeyPath = path.join(os.tmpdir(), `sa-key-${Date.now()}.json`);
        await fs.writeFile(tempKeyPath, JSON.stringify(req.body.serviceAccount));

        const config = {
            source: 'gcp', // Hardcode for Google Cloud
            output: 'json', // Always return JSON as requested
            console: 'none', // Suppress console output within the function
            google: {
                key_file: tempKeyPath, // Point to the temporary key file
            },
            // Optional: allow the user to specify which plugins to run
            plugins: req.body.plugins || null, // e.g., ['gce', 'gcs']
            // Optional: allow the user to specify a compliance standard
            compliance: req.body.compliance || null // e.g., 'pci'
        };

        console.log(`Starting CloudSploit scan for project: ${req.body.serviceAccount.project_id}`);
        console.log(`Using plugins: ${config.plugins ? config.plugins.join(', ') : 'all'}`);

        // --- Execute Scan and Wait for Results ---
        // By awaiting our promise-wrapped function, we ensure the Cloud Function
        // does not terminate before all scans are complete.
        const results = await runCloudSploit(config);

        console.log('CloudSploit scan completed successfully.');
        res.status(200).json(results);

    } catch (error) {
        console.error('An error occurred during the CloudSploit scan:', error);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    } finally {
        // --- Cleanup ---
        // Always attempt to delete the temporary service account key file.
        if (tempKeyPath) {
            try {
                await fs.unlink(tempKeyPath);
            } catch (cleanupError) {
                console.error(`Failed to clean up temporary key file: ${tempKeyPath}`, cleanupError);
            }
        }
    }
};
