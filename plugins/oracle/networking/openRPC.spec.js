var expect = require('chai').expect;
const plugin = require('./openRPC');

const securityLists = [
    {
      "compartmentId": "compartment-1",
      "displayName": "list1",
      "egressSecurityRules": [],
      "freeformTags": {},
      "id": "list1",
      "ingressSecurityRules": [
        {
          "isStateless": false,
          "protocol": "17",
          "source": "0.0.0.0/0",
          "sourceType": "CIDR_BLOCK",
          "tcpOptions": {
            "destinationPortRange": {
              "max": 135,
              "min": 135
            },
            "sourcePortRange": {
              "max": 135,
              "min": 135
            }
          }
        }
      ],
      "lifecycleState": "AVAILABLE",
      "timeCreated": "2022-04-17T01:16:32.366Z",
      "vcnId": "vcn1"
    },
    {
      "compartmentId": "compartment-1",
      "displayName": "list2",
      "id": "list2",
      "ingressSecurityRules": [
        {
          "isStateless": false,
          "protocol": "6",
          "source": "0.0.0.0/0",
          "sourceType": "CIDR_BLOCK",
          "tcpOptions": {
            "destinationPortRange": {
              "max": 22,
              "min": 22
            }
          }
        }
      ],
      "lifecycleState": "AVAILABLE",
      "timeCreated": "2022-01-09T13:02:20.425Z",
      "vcnId": "vcn1"
    }
  ];

const securityRules =   [
    {
      "direction": "INGRESS",
      "id": "1",
      "isStateless": false,
      "isValid": true,
      "protocol": "all",
      "source": "10.1.0.0/16",
      "sourceType": "CIDR_BLOCK",
      "timeCreated": "2022-01-09T13:03:48.937Z",
      "networkSecurityGroups": "group1"
    },
    {
      "direction": "INGRESS",
      "id": "2",
      "isStateless": false,
      "isValid": true,
      "protocol": "17",
      "source": "0.0.0.0/0",
      "sourceType": "CIDR_BLOCK",
      "timeCreated": "2022-04-17T12:16:46.679Z",
      "tcpOptions": {
        "destinationPortRange": {
          "max": 135,
          "min": 135
        },
        "sourcePortRange": {
          "max": 135,
          "min": 135
        }
      },
      "networkSecurityGroups": "group1"
    }
  ]
const networkSecurityGroups = [
    {
      "compartmentId": "compartment-1",
      "displayName": "firstgroup",
      "id": "group1",
      "lifecycleState": "AVAILABLE",
      "timeCreated": "2022-01-09T13:03:47.999Z",
      "vcnId": "vcn1"
    }
  ]
const createCache = (listsData, listsErr, groupsData, groupsErr, rulesData, rulesErr,) => {
    return {

        securityList: {
            list: {
                "us-ashburn-1": {
                    data: listsData,
                    err: listsErr
                }
            }
        },
        securityRule: {
            list: {
                "us-ashburn-1": {
                    data: rulesData,
                    err: rulesErr
                }
            }
        },
        networkSecurityGroup: {
            list: {
                "us-ashburn-1": {
                    data: groupsData,
                    err: groupsErr
                }
            }
        },
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
       
    };
};



describe('openRPC', function () {
    describe('run', function () {
        it('should give unknown if unable to query for security lists', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                ['error'],
                networkSecurityGroups,
                null,
                securityRules,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown if unable to query for security rules', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                securityLists[1],
                null,
                networkSecurityGroups,
                null,
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should PASS if no security lists or ruls are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security rules or lists found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                null,
                networkSecurityGroups,
                null,
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should PASS if no open ports found in security lists', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[1]],
                null,
                networkSecurityGroups,
                null, 
                securityRules,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should PASS if no open ports found in network security groups', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[1]],
                null,
                networkSecurityGroups,
                null, 
                [securityRules[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should FAIL if security list has RPC port open to public', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has RPC: TCP port 135 open to')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[0]],
                null,
                networkSecurityGroups,
                null,
                [securityRules[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should FAIL if network security group has RPC port open to public', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(2)
                expect(results[1].message).to.include('has RPC: TCP port 135 open to')
                expect(results[1].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[1]],
                null,
                networkSecurityGroups,
                null,
                [securityRules[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });
    });
});
