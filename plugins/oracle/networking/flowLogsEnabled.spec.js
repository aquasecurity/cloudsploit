var expect = require('chai').expect;
var plugin = require('./flowLogsEnabled');

const logs = [
    {
        "id": "ocid1.log.oc1.log11111111",
        "logGroupId": "ocid1.loggroup.oc1.loggroup11111",
        "displayName": "subnet_log",
        "isEnabled": true,
        "lifecycleState": "ACTIVE",
        "logType": "SERVICE",
        "configuration": {
          "compartmentId": "ocid1.tenancy.oc1.1111111111111",
          "source": {
            "sourceType": "OCISERVICE",
            "service": "flowlogs",
            "resource": "ocid1.subnet.oc1.iad.subnet1",
            "category": "all",
            "parameters": {}
          },
          "archiving": {
            "isEnabled": false
          }
        },
        "freeformTags": {},
        "timeCreated": "2022-07-15T00:25:53.258Z",
        "timeLastModified": "2022-07-15T00:25:53.258Z",
        "retentionDuration": 30,
        "compartmentId": "ocid1.tenancy.oc1.1111111111111",
        "logGroups": "ocid1.loggroup.oc1.loggroup11111"
      }
]

const createCache = (err, data) => {
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

        subnet: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        log: {
            list: {
                'us-ashburn-1': {
                    err: null,
                    data: logs
                }
            }
        }
    }
};

describe('flowLogsEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a subnet error occurs or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for subnets')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no subnets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No subnets found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the subnet does not have flow logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The subnet does not have flow logs enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    
                    {
                        "cidrBlock": "10.0.1.0/24",
                        "compartmentId": "ocid1.tenancy.oc1.1111111111111",
                        "definedTags": {},
                        "displayName": "subnet1",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.subnet2",
                        "lifecycleState": "AVAILABLE",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.list11111"
                        ],
                        "timeCreated": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.vcn111111",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if the subnet has flow logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The subnet has flow logs enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "cidrBlock": "10.0.1.0/24",
                        "compartmentId": "ocid1.tenancy.oc1.1111111111111",
                        "definedTags": {},
                        "displayName": "subnet1",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.subnet1",
                        "lifecycleState": "AVAILABLE",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.list11111"
                        ],
                        "timeCreated": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.vcn111111",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})