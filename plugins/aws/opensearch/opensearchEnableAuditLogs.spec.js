const expect = require('chai').expect;
const osAccessFromIps = require('./opensearchEnableAuditLogs');

const domainNames = [
    {
        "DomainName": "test-domain3-1"
    },
    {
        "DomainName": "test-domain-2"
    }
];

const domains = [
    {
       
    "DomainStatus": {
      "DomainId": "1123456654321/test-domain-1",
      "DomainName": "test-domain-1",
      "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-1",
       "LogPublishingOptions": {
                        "AUDIT_LOGS": {
                            "Enabled": false
                        }
                    }
    },
},
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-2",
            "DomainName": "test-domain-2",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-2",
            "Created": true,
            "Deleted": false,
        }
    }
];
