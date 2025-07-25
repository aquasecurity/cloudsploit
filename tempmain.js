/**
 * This file provides a clean, promise-based wrapper for the CloudSploit engine
 * and an HTTP handler to deploy it as a Google Cloud Function.
 */

// engine.js is the core CloudSploit scanner.
const engine = require('./engine.js');
const fs = require('fs').promises;
const path = require('path'); // NEW: Import the path module

/**
 * Reads a category directory and returns a list of plugin names.
 * @param {string} category - The name of the category (e.g., "compute").
 * @returns {Promise<Array<string>>} A promise that resolves to an array of plugin names.
 */
// NEW: Helper function to dynamically load plugins.
async function getPluginsFromCategory(category) {
    // Assumes plugins are located in './plugins/google/' relative to this file.
    const categoryPath = path.join(__dirname, 'plugins', 'google', category);

    try {
        console.log(`Reading plugins from directory: ${categoryPath}`);
        const files = await fs.readdir(categoryPath);

        // Filter for .js files and map them to their name without the extension.
        const pluginNames = files
            .filter(file => file.endsWith('.js'))
            .map(file => path.basename(file, '.js'));

        console.log(`Found ${pluginNames.length} plugins in category "${category}".`);
        return pluginNames;
    } catch (err) {
        console.error(`Error reading plugin category "${category}": ${err.message}`);
        // Return an empty array if the directory doesn't exist or can't be read.
        return [];
    }
}

/**
 * Executes a CloudSploit scan by wrapping the callback-based engine in a Promise.
 * It also handles filtering of "OK" results if specified in the settings.
 *
 * @param {object} cloudConfig - The cloud credentials object (i.e., the service account key).
 * @param {object} settings - The scan settings object.
 * @returns {Promise<Array>} A promise that resolves with the array of scan results.
 */
// NEW: `runScan` is now an async function to use our new helper.
async function runScan(cloudConfig, settings) {
    // NEW: Dynamically build the plugin list if a category is provided.
    if (settings && settings.category) {
        console.log(`A category was provided: "${settings.category}". Dynamically loading plugins...`);
        const plugins = await getPluginsFromCategory(settings.category);
        if (plugins && plugins.length > 0) {
            // This injects the dynamic list into the settings that will be passed to the engine.
            settings.list_of_plugins = plugins;
        }
    }

    // Define default settings and merge them with user-provided settings.
    const finalSettings = {
        cloud: 'google',
        console: 'none',
        ignore_ok: true,
        ...settings
    };

    // This is the portion of code that handles the callback.
    return new Promise((resolve, reject) => {
        const callback = (err, results) => {
            if (err) {
                console.error('Error reported from CloudSploit engine:', err);
                return reject(err);
            }
            console.log('Engine callback received successfully. Processing results...');
            if (finalSettings.ignore_ok) {
                const filteredResults = {};
                for (const pluginName in results) {
                    const pluginResults = results[pluginName];
                    const nonOkResults = pluginResults.filter(result => result.status !== 0);
                    if (nonOkResults.length > 0) {
                        filteredResults[pluginName] = nonOkResults;
                    }
                }
                resolve(filteredResults);
            } else {
                resolve(results);
            }
        };

        console.log('Calling the CloudSploit engine...');
        engine(cloudConfig, finalSettings, callback);
    });
}

/**
 * Main HTTP Cloud Function handler.
 */
exports.cloudsploitScanner = async (req, res) => {
    // ... (This entire function does not need to change)
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    if (!req.body || !req.body.serviceAccount || !req.body.serviceAccount.project_id) {
        return res.status(400).send('Bad Request: "serviceAccount" key missing or it does not contain a "project_id" field.');
    }
    const cloudConfig = req.body.serviceAccount;
    cloudConfig.project = cloudConfig.project_id;
    const settings = req.body.settings || {};
    try {
        const results = await runScan(cloudConfig, settings);
        res.status(200).json(results);
    } catch (error) {
        console.error('An error occurred during the CloudSploit scan:', error);
        res.status(500).send(`Internal Server Error: ${error.message || error}`);
    }
};

// --- LOCAL TESTING EXAMPLE ---
if (require.main === module) {
    (async () => {
        console.log('--- RUNNING IN LOCAL TEST MODE ---');
        const testKeyPath = './key.json';
        let serviceAccountKey;
        try {
            const keyData = await fs.readFile(testKeyPath, 'utf8');
            serviceAccountKey = JSON.parse(keyData);
            if (!serviceAccountKey.project_id) {
                throw new Error('The key.json file is missing the required "project_id" field.');
            }
            console.log(`Successfully loaded service account key for project: ${serviceAccountKey.project_id}`);
        } catch (err) {
            console.error(`\nError: Could not read or parse "${testKeyPath}".`);
            console.error(err.message);
            process.exit(1);
        }
        const cloudConfig = serviceAccountKey;
        cloudConfig.project = cloudConfig.project_id;
        
        // NEW: We now provide a category instead of a hardcoded list.
        const settings = {
            category: "compute", // Tell the scanner to run all plugins in the "compute" category.
        };

        try {
            console.log(`\nAttempting to run scan...`);
            const scanResults = await runScan(cloudConfig, settings);
            console.log('\n--- SCAN RESULTS (JSON) ---');
            console.log(JSON.stringify(scanResults, null, 2));
        } catch (error) {
            console.error('\n--- SCAN FAILED ---');
            console.error('The runScan function rejected its promise:', error);
        }
        console.log('\n--- LOCAL TEST MODE FINISHED ---');
    })();
}