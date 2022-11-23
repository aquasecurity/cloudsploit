// CloudSploit config file

module.exports = {
    credentials: {
        aws: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // access_key: process.env.AWS_ACCESS_KEY_ID || '',
            // secret_access_key: process.env.AWS_SECRET_ACCESS_KEY || '',
            // session_token: process.env.AWS_SESSION_TOKEN || '',
            // plugins_remediate: ['bucketEncryptionInTransit']
        },
        aws_remediate: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // access_key: process.env.AWS_ACCESS_KEY_ID || '',
            // secret_access_key: process.env.AWS_SECRET_ACCESS_KEY || '',
            // session_token: process.env.AWS_SESSION_TOKEN || '',
        },
        azure: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            application_id: process.env.AZURE_APPLICATION_ID || '8aa9db84-2dd8-4b07-a446-f15fc92133b5',
            key_value: process.env.AZURE_KEY_VALUE || 'wJZ8Q~20VxWgZGN3DJ1NF0AzrBkyh84_C0jnQb1w',
            directory_id: process.env.AZURE_DIRECTORY_ID || '2d4f0836-5935-47f5-954c-14e713119ac2',
            subscription_id: 'dce7d0ad-ebf6-437f-a3b0-28fc0d22117e'
            // subscription_id: process.env.AZURE_SUBSCRIPTION_ID || ''
        },
        azure_remediate: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // application_id: process.env.AZURE_APPLICATION_ID || '',
            // key_value: process.env.AZURE_KEY_VALUE || '',
            // directory_id: process.env.AZURE_DIRECTORY_ID || '',
            // subscription_id: process.env.AZURE_SUBSCRIPTION_ID || ''
        },
        google_remediate: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: process.env.GOOGLE_APPLICATION_CREDENTIALS || '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // project: process.env.GOOGLE_PROJECT_ID || 'my-project',
            // client_email: process.env.GOOGLE_CLIENT_EMAIL || 'cloudsploit@your-project-name.iam.gserviceaccount.com',
            // private_key: process.env.GOOGLE_PRIVATE_KEY || '-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n'
        },
        google: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: process.env.GOOGLE_APPLICATION_CREDENTIALS || '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // project: process.env.GOOGLE_PROJECT_ID || 'my-project',
            // client_email: process.env.GOOGLE_CLIENT_EMAIL || 'cloudsploit@your-project-name.iam.gserviceaccount.com',
            // private_key: process.env.GOOGLE_PRIVATE_KEY || '-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n'
        },
        oracle: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // tenancy_id: process.env.ORACLE_TENANCY_ID || 'ocid1.tenancy.oc1..',
            // compartment_id: process.env.ORACLE_COMPARTMENT_ID || 'ocid1.compartment.oc1..',
            // user_id: process.env.ORACLE_USER_ID || 'ocid1.user.oc1..',
            // key_fingerprint: process.env.ORACLE_KEY_FINGERPRINT || 'YOURKEYFINGERPRINT',
            // key_value: process.env.ORACLE_KEY_VALUE || '-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n'
        },
        github: {
            // OPTION 1: If using a credential JSON file, enter the path below
            // credential_file: '/path/to/file.json',
            // OPTION 2: If using hard-coded credentials, enter them below
            // token: process.env.GITHUB_TOKEN || '',
            // url: process.env.GITHUB_URL || 'https://api.github.com',
            // login: process.env.GITHUB_LOGIN || 'myusername',
            // organization: process.env.GITHUB_ORG || false
        }
    }
};