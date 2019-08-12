var service =
    {
        amazon: {
            'us-phoenix-1': '<object_storage_namespace>.compat.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': '<object_storage_namespace>.compat.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': '<object_storage_namespace>.compat.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': '<object_storage_namespace>.compat.uk-london-1.oraclecloud.com',
            'ca-toronto-1': '<object_storage_namespace>.compat.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': '<object_storage_namespace>.compat.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': '<object_storage_namespace>.compat.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': '<object_storage_namespace>.compat.ap-tokyo-1.oraclecloud.com'
        },
        myServices: 'itra.oraclecloud.com',
        kms: {
            'us-phoenix-1': 'kms.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'kms.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'kms.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'kms.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'kms.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'kms.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'kms.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'kms.ap-tokyo-1.oraclecloud.com'
        },
        audit: {
            'us-phoenix-1': 'audit.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'audit.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'audit.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'audit.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'audit.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'audit.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'audit.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'audit.ap-tokyo-1.oraclecloud.com'
        },
        containerEngine: {
            'us-phoenix-1': 'containerengine.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'containerengine.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'containerengine.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'containerengine.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'containerengine.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'containerengine.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'containerengine.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'containerengine.ap-tokyo-1.oraclecloud.com'
        },
        database: {
            'us-phoenix-1': 'database.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'database.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'database.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'database.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'database.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'database.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'database.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'database.ap-tokyo-1.oraclecloud.com'
        },
        iam: {
            'us-phoenix-1': 'identity.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'identity.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'identity.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'identity.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'identity.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'identity.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'identity.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'identity.ap-tokyo-1.oraclecloud.com'
        },
        loadBalance: {
            'us-phoenix-1': 'iaas.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'iaas.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'iaas.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'iaas.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'iaas.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'iaas.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'iaas.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'iaas.ap-tokyo-1.oraclecloud.com'
        },
        core: {
            'us-phoenix-1': 'iaas.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'iaas.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'iaas.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'iaas.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'iaas.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'iaas.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'iaas.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'iaas.ap-tokyo-1.oraclecloud.com'
        },
        email: {
            'us-phoenix-1': 'email.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'email.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'email.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'email.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'email.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'email.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'email.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'email.ap-tokyo-1.oraclecloud.com'
        },
        dns: {
            'us-phoenix-1': 'dns.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'dns.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'dns.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'dns.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'dns.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'dns.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'dns.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'dns.ap-tokyo-1.oraclecloud.com'
        },
        fileStorage: {
            'us-phoenix-1': 'filestorage.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'filestorage.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'filestorage.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'filestorage.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'filestorage.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'filestorage.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'filestorage.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'filestorage.ap-tokyo-1.oraclecloud.com'
        },
        internetIntel: {
            'us-phoenix-1': 'cloudanalytics.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'cloudanalytics.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'cloudanalytics.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'cloudanalytics.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'cloudanalytics.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'cloudanalytics.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'cloudanalytics.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'cloudanalytics.ap-tokyo-1.oraclecloud.com'
        },
        search: {
            'us-phoenix-1': 'query.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'query.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'query.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'query.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'query.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'query.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'query.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'query.ap-tokyo-1.oraclecloud.com'
        },
        myService: {
            'us-phoenix-1': 'itra.oraclecloud.com/',
            'us-ashburn-1': 'itra.oraclecloud.com/',
            'eu-frankfurt-1': 'itra.oraclecloud.com/',
            'uk-london-1': 'itra.oraclecloud.com/',
            'ca-toronto-1': 'itra.oraclecloud.com/',
            'ap-mumbai-1': 'itra.oraclecloud.com/',
            'ap-seoul-1': 'itra.oraclecloud.com/',
            'ap-tokyo-1': 'itra.oraclecloud.com/',
        },
        objectStore: {
            'us-phoenix-1': 'objectstorage.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'objectstorage.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'objectstorage.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'objectstorage.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'objectstorage.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'objectstorage.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'objectstorage.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'objectstorage.ap-tokyo-1.oraclecloud.com'
        },
        waas: {
            'us-phoenix-1': 'waas.us-phoenix-1.oraclecloud.com',
            'us-ashburn-1': 'waas.us-ashburn-1.oraclecloud.com',
            'eu-frankfurt-1': 'waas.eu-frankfurt-1.oraclecloud.com',
            'uk-london-1': 'waas.uk-london-1.oraclecloud.com',
            'ca-toronto-1': 'waas.ca-toronto-1.oraclecloud.com',
            'ap-mumbai-1': 'waas.ap-mumbai-1.oraclecloud.com',
            'ap-seoul-1': 'waas.ap-seoul-1.oraclecloud.com',
            'ap-tokyo-1': 'waas.ap-tokyo-1.oraclecloud.com'
        }
    };

module.exports = {
    service: service
};
