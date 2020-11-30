var expect = require('chai').expect;
const danglingDnsRecords = require('./danglingDnsRecords');

const listHostedZones = [
    {
        "Id": "/hostedzone/Z0959845393J2LOUSNVSK",
        "Name": "testfr.com.",
        "CallerReference": "d042e53d-7b8b-4974-94e9-8305af0c6acb",
        "Config": {
            "Comment": "",
            "PrivateZone": false
        },
        "ResourceRecordSetCount": 4
    }
];

const listResourceRecordSets = [
    {
        ResourceRecordSets:  [
            {
                "Name": "eip.testfr.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [
                    {
                        "Value": "55.90.14.155"
                    }
                ]
            }
        ]
    },
    {
        ResourceRecordSets:  [
            {
                "Name": "ec2.testfr.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [
                    {
                        "Value": "172.31.28.00"
                    }
                ]
            },
        ]
    },
];

const describeAddresses = [
    {
        "PublicIp": "55.90.14.155",
        "AllocationId": "eipalloc-02fbee66ba40a5920",
        "Domain": "vpc",
        "PublicIpv4Pool": "amazon",
        "NetworkBorderGroup": "us-east-1"
    }
];

const createCache = (zones, recordSets, addresses) => {
    var zoneId = (zones && zones.length && zones[0].Id) ? zones[0].Id : null;
    return {
        route53: {
            listHostedZones: {
                'us-east-1': {
                    data: zones
                },
            },
            listResourceRecordSets: {
                'us-east-1': {
                    [zoneId]: {
                        data: recordSets
                    },
                },
            },
        },
        ec2: {
            describeAddresses: {
                'us-east-1': {
                    data: addresses
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        route53: {
            listHostedZones: {
                'us-east-1': {
                    err: {
                        message: 'error listing Route 53 hosted zones'
                    },
                },
            },
            listResourceRecordSets: {
                'us-east-1': {
                    err: {
                        message: 'error listing resource record sets'
                    },
                },
            },
        },
        ec2: {
            describeAddresses: {
                'us-east-1': {
                    err: {
                        message: 'error describing elastic IP addresses'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        route53: {
            listHostedZones: {
                'us-east-1': null,
            },
            listResourceRecordSets: {
                'us-east-1': null,
            },
        },
        ec2: {
            describeAddresses: {
                'us-east-1': null
            },
        },
    };
};

describe('danglingDnsRecords', function () {
    describe('run', function () {
        it('should PASS if Hosted Zone does not have any dangling DNS records', function (done) {
            const cache = createCache([listHostedZones[0]], listResourceRecordSets[0], [describeAddresses[0]]);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Hosted Zone has DNS records', function (done) {
            const cache = createCache([listHostedZones[0]], listResourceRecordSets[1], [describeAddresses[0]]);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Hosted Zone has DNS records', function (done) {
            const cache = createCache([listHostedZones[0]], listResourceRecordSets[1], []);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no hosted zones found', function (done) {
            const cache = createCache([]);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no resource record sets found', function (done) {
            const cache = createCache([listHostedZones[0]], {}, []);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to list hosted zones', function (done) {
            const cache = createErrorCache();
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should UNKNOWN if unable to list resource record sets', function (done) {
            const cache = createCache([listHostedZones[0]], null, []);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe elastic IP addresses', function (done) {
            const cache = createCache([listHostedZones[0]], []);
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if list hosted zones response not found', function (done) {
            const cache = createNullCache();
            danglingDnsRecords.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
