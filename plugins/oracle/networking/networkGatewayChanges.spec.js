var expect = require('chai').expect;
var plugin = require('./networkGatewayChanges');

const rules = [
    {
        id: 'ocid1.eventrule.oc1.rule1',
        displayName: 'Rule 1',
        lifecycleState: 'ACTIVE',
        condition: `{"eventType":["com.oraclecloud.virtualnetwork.createdrg","com.oraclecloud.virtualnetwork.updatedrg","com.oraclecloud.virtualnetwork.deletedrg",
        "com.oraclecloud.virtualnetwork.createdrgattachment", "com.oraclecloud.virtualnetwork.updatedrgattachment", "com.oraclecloud.virtualnetwork.deletedrgattachment",
        "com.oraclecloud.virtualnetwork.createinternetgateway", "com.oraclecloud.virtualnetwork.updateinternetgateway", "com.oraclecloud.virtualnetwork.deleteinternetgateway", "com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment",
        "com.oraclecloud.virtualnetwork.createlocalpeeringgateway", "com.oraclecloud.virtualnetwork.updatelocalpeeringgateway", "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.begin", "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end", "com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment",
        "com.oraclecloud.natgateway.createnatgateway", "com.oraclecloud.natgateway.updatenatgateway", "com.oraclecloud.natgateway.deletenatgateway", "com.oraclecloud.natgateway.changenatgatewaycompartment",
        "com.oraclecloud.servicegateway.attachserviceid", "com.oraclecloud.servicegateway.detachserviceid", "com.oraclecloud.servicegateway.createservicegateway", "com.oraclecloud.servicegateway.updateservicegateway", "com.oraclecloud.servicegateway.deleteservicegateway.begin", "com.oraclecloud.servicegateway.deleteservicegateway.end", "com.oraclecloud.servicegateway.changeservicegatewaycompartment"
        ],"data":{}}`,
        compartmentId: 'ocid1.tenancy.oc1.111111111',
        isEnabled: true,
        timeCreated: '2022-07-03T23:57:52.769Z',
    },
    {
        id: 'ocid1.eventrule.oc1.rule1',
        displayName: 'Rule 1',
        lifecycleState: 'ACTIVE',
        condition: '{"eventType":[ "com.oraclecloud.virtualnetwork.createinternetgateway", "com.oraclecloud.virtualnetwork.updateinternetgateway", "com.oraclecloud.virtualnetwork.createinternetgateway"],"data":{}}',
        compartmentId: 'ocid1.tenancy.oc1.111111111',
        isEnabled: true,
        timeCreated: '2022-07-03T23:57:52.769Z',
    },
    {
        id: 'ocid1.eventrule.oc1.iad.abuwcljsa53hgf43hbifj3qmhewwgttyedhcngvbb3yyqqzgegtc4dpz2zca',
        displayName: 'rule 2',
        description: null,
        lifecycleState: 'ACTIVE',
        condition: '{"eventType":["com.oraclecloud.objectstorage.createbucket"],"data":{}}',
        compartmentId: 'ocid1.tenancy.oc1.111111111',
        isEnabled: true,
        timeCreated: '2022-07-04T01:06:54.834Z'
    }

];


const createCache = (err, rules) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        rules: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: rules
                }
            }
        },
    }
};

describe('networkGatewayChanges', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for rules', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['err'],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no rules found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No rules found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no network gateway rules are configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No event rules are configured for')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [rules[2]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if Event rules are missing for some network gateway changes', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Event rules are missing for')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [rules[1]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if event rules are configured for all network gateway changes', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Event rules are configured for all')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [rules[0]]
            );

            plugin.run(cache, {}, callback);
        })


    });
});