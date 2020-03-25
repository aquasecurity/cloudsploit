var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./lbNSGEnabled');

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
        loadBalancer: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },

    }
};

describe('lbNSGEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a load balancer error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for load balancers')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no load balancer records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No load balancers found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if there is a load balancer without a network security group', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Load Balancer has no network security groups connected')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "ocid1.loadbalancer.oc1.iad.aaaaaaaabxwhnvfngpkvelzxh4xv7rx7ucalqyccvh54zux2khomabvsd5xq",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "lb_2019-0624-1444",
                        "lifecycleState": "ACTIVE",
                        "timeCreated": "2019-06-24T21:45:47.029Z",
                        "ipAddresses": [
                            {
                                "ipAddress": "129.213.180.159",
                                "isPublic": true
                            }
                        ],
                        "shapeName": "100Mbps",
                        "isPrivate": false,
                        "subnetIds": [
                            "ocid1.subnet.oc1.iad.aaaaaaaaebijfibsowmrjqyegn74qtqv5iiuflihlqw6sz23pm4h4jbj2fhq",
                            "ocid1.subnet.oc1.iad.aaaaaaaaiordekrskkkddh7zhchrgvh72fv2tl4jt7zq3unrlc53dpi3jz5a"
                        ],
                        "networkSecurityGroupIds": [],
                        "listeners": {
                            "listener_lb_2019-0624-1444": {
                                "name": "listener_lb_2019-0624-1444",
                                "defaultBackendSetName": "bs_lb_2019-0624-1444",
                                "port": 8080,
                                "protocol": "HTTP",
                                "connectionConfiguration": {
                                    "idleTimeout": 60
                                },
                                "ruleSetNames": []
                            }
                        },
                        "hostnames": {},
                        "certificates": {},
                        "backendSets": {
                            "bs_lb_2019-0624-1444": {
                                "name": "bs_lb_2019-0624-1444",
                                "policy": "ROUND_ROBIN",
                                "backends": [],
                                "healthChecker": {
                                    "protocol": "HTTP",
                                    "urlPath": "/",
                                    "port": 80,
                                    "returnCode": 200,
                                    "retries": 3,
                                    "timeoutInMillis": 3000,
                                    "intervalInMillis": 100000,
                                    "responseBodyRegex": ""
                                },
                                "sessionPersistenceConfiguration": {
                                    "cookieName": "*",
                                    "disableFallback": false
                                }
                            }
                        },
                        "pathRouteSets": {},
                        "freeformTags": {},
                        "definedTags": {},
                        "ruleSets": {}
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if all load balancers have network security groups', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All Load balancers have network security groups Connected')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                    "id": "ocid1.loadbalancer.oc1.iad.aaaaaaaabxwhnvfngpkvelzxh4xv7rx7ucalqyccvh54zux2khomabvsd5xq",
                    "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                    "displayName": "lb_2019-0624-1444",
                    "lifecycleState": "ACTIVE",
                    "timeCreated": "2019-06-24T21:45:47.029Z",
                    "ipAddresses": [
                        {
                            "ipAddress": "129.213.180.159",
                            "isPublic": true
                        }
                    ],
                    "shapeName": "100Mbps",
                    "isPrivate": false,
                    "subnetIds": [
                        "ocid1.subnet.oc1.iad.aaaaaaaaebijfibsowmrjqyegn74qtqv5iiuflihlqw6sz23pm4h4jbj2fhq",
                        "ocid1.subnet.oc1.iad.aaaaaaaaiordekrskkkddh7zhchrgvh72fv2tl4jt7zq3unrlc53dpi3jz5a"
                    ],
                    "networkSecurityGroupIds": ['hello', 'world'],
                    "listeners": {
                        "listener_lb_2019-0624-1444": {
                            "name": "listener_lb_2019-0624-1444",
                            "defaultBackendSetName": "bs_lb_2019-0624-1444",
                            "port": 8080,
                            "protocol": "HTTP",
                            "connectionConfiguration": {
                                "idleTimeout": 60
                            },
                            "ruleSetNames": []
                        }
                    },
                    "hostnames": {},
                    "certificates": {},
                    "backendSets": {
                        "bs_lb_2019-0624-1444": {
                            "name": "bs_lb_2019-0624-1444",
                            "policy": "ROUND_ROBIN",
                            "backends": [],
                            "healthChecker": {
                                "protocol": "HTTP",
                                "urlPath": "/",
                                "port": 80,
                                "returnCode": 200,
                                "retries": 3,
                                "timeoutInMillis": 3000,
                                "intervalInMillis": 100000,
                                "responseBodyRegex": ""
                            },
                            "sessionPersistenceConfiguration": {
                                "cookieName": "*",
                                "disableFallback": false
                            }
                        }
                    },
                    "pathRouteSets": {},
                    "freeformTags": {},
                    "definedTags": {},
                    "ruleSets": {}
                }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})