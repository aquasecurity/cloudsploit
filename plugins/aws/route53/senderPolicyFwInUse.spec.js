var expect = require('chai').expect;
const senderPolicyFwInUse = require('./senderPolicyFwInUse');

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
                "Type": "TXT",
                "TTL": 300,
                "ResourceRecords": [
                    {
                        "Value": "v=spf1 ip4:192.168.0.5/16 -all"
                    }
                ]
            }
        ]
    },
    {
        ResourceRecordSets:  [
            {
                "Name": "ec2.testfr.com.",
                "Type": "TXT",
                "TTL": 300,
                "ResourceRecords": [
                    {
                        "Value": "172.31.28.00"
                    }
                ]
            },
        ]
    }
];


const createCache = (zones, recordSets) => {
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
    };
};

describe('senderPolicyFwInUse', function () {
    describe('run', function () {
        it('should PASS if Hosted Zone has SPF', function (done) {
            const cache = createCache([listHostedZones[0]], listResourceRecordSets[0]);
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Hosted Zone does not have SPF', function (done) {
            const cache = createCache([listHostedZones[0]], listResourceRecordSets[1]);
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no hosted zones found', function (done) {
            const cache = createCache([]);
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no resource record sets found', function (done) {
            const cache = createCache([listHostedZones[0]], {});
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to list hosted zones', function (done) {
            const cache = createErrorCache();
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should UNKNOWN if unable to list resource record sets', function (done) {
            const cache = createCache([listHostedZones[0]], null);
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list hosted zones response not found', function (done) {
            const cache = createNullCache();
            senderPolicyFwInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
