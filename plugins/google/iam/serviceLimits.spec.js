var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serviceLimits');

const createCache = (err, data) => {
    return {
        projects: {
            get: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('serviceLimits', function () {
    describe('run', function () {
        it('should give unknown result if a project error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query projects:')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no project records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No projects found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if the projects services are all within service limits', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All resources are within the service limits')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "compute#project",
                        "id": "2548647434039838416",
                        "creationTimestamp": "2019-06-19T11:00:31.059-07:00",
                        "name": "frost-forest-281330",
                        "commonInstanceMetadata": {
                            "kind": "compute#metadata",
                            "fingerprint": "bur0P6caU8Y="
                        },
                        "quotas": [
                            {
                                "metric": "SNAPSHOTS",
                                "limit": 5000,
                                "usage": 0
                            },
                            {
                                "metric": "NETWORKS",
                                "limit": 15,
                                "usage": 3
                            },
                            {
                                "metric": "FIREWALLS",
                                "limit": 200,
                                "usage": 3
                            },
                            {
                                "metric": "IMAGES",
                                "limit": 2000,
                                "usage": 1
                            },
                            {
                                "metric": "STATIC_ADDRESSES",
                                "limit": 21,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTES",
                                "limit": 250,
                                "usage": 63
                            },
                            {
                                "metric": "FORWARDING_RULES",
                                "limit": 45,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_POOLS",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "HEALTH_CHECKS",
                                "limit": 150,
                                "usage": 1
                            },
                            {
                                "metric": "IN_USE_ADDRESSES",
                                "limit": 69,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_INSTANCES",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTP_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "URL_MAPS",
                                "limit": 30,
                                "usage": 2
                            },
                            {
                                "metric": "BACKEND_SERVICES",
                                "limit": 9,
                                "usage": 1
                            },
                            {
                                "metric": "INSTANCE_TEMPLATES",
                                "limit": 300,
                                "usage": 1
                            },
                            {
                                "metric": "TARGET_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            },
                            {
                                "metric": "VPN_TUNNELS",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "BACKEND_BUCKETS",
                                "limit": 9,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTERS",
                                "limit": 10,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_SSL_PROXIES",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTPS_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "SSL_CERTIFICATES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "SUBNETWORKS",
                                "limit": 175,
                                "usage": 60
                            },
                            {
                                "metric": "TARGET_TCP_PROXIES",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "SECURITY_POLICIES",
                                "limit": 10,
                                "usage": 1
                            },
                            {
                                "metric": "SECURITY_POLICY_RULES",
                                "limit": 100,
                                "usage": 0
                            },
                            {
                                "metric": "NETWORK_ENDPOINT_GROUPS",
                                "limit": 300,
                                "usage": 0
                            },
                            {
                                "metric": "INTERCONNECTS",
                                "limit": 6,
                                "usage": 0
                            },
                            {
                                "metric": "GLOBAL_INTERNAL_ADDRESSES",
                                "limit": 5000,
                                "usage": 1
                            },
                            {
                                "metric": "VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            },
                            {
                                "metric": "EXTERNAL_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/frost-forest-281330",
                        "defaultServiceAccount": "845005677082-compute@developer.gserviceaccount.com",
                        "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS",
                        "defaultNetworkTier": "PREMIUM"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give warning result if the projects services are getting close to the service limits', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('The following services are over the 75%')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "compute#project",
                        "id": "2548647434039838416",
                        "creationTimestamp": "2019-06-19T11:00:31.059-07:00",
                        "name": "frost-forest-281330",
                        "commonInstanceMetadata": {
                            "kind": "compute#metadata",
                            "fingerprint": "bur0P6caU8Y="
                        },
                        "quotas": [
                            {
                                "metric": "SNAPSHOTS",
                                "limit": 5000,
                                "usage": 0
                            },
                            {
                                "metric": "NETWORKS",
                                "limit": 15,
                                "usage": 3
                            },
                            {
                                "metric": "FIREWALLS",
                                "limit": 200,
                                "usage": 3
                            },
                            {
                                "metric": "IMAGES",
                                "limit": 2000,
                                "usage": 1
                            },
                            {
                                "metric": "STATIC_ADDRESSES",
                                "limit": 21,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTES",
                                "limit": 250,
                                "usage": 63
                            },
                            {
                                "metric": "FORWARDING_RULES",
                                "limit": 45,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_POOLS",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "HEALTH_CHECKS",
                                "limit": 150,
                                "usage": 1
                            },
                            {
                                "metric": "IN_USE_ADDRESSES",
                                "limit": 69,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_INSTANCES",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTP_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "URL_MAPS",
                                "limit": 30,
                                "usage": 2
                            },
                            {
                                "metric": "BACKEND_SERVICES",
                                "limit": 9,
                                "usage": 1
                            },
                            {
                                "metric": "INSTANCE_TEMPLATES",
                                "limit": 300,
                                "usage": 1
                            },
                            {
                                "metric": "TARGET_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            },
                            {
                                "metric": "VPN_TUNNELS",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "BACKEND_BUCKETS",
                                "limit": 9,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTERS",
                                "limit": 10,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_SSL_PROXIES",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTPS_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "SSL_CERTIFICATES",
                                "limit": 30,
                                "usage": 22
                            },
                            {
                                "metric": "SUBNETWORKS",
                                "limit": 175,
                                "usage": 60
                            },
                            {
                                "metric": "TARGET_TCP_PROXIES",
                                "limit": 30,
                                "usage": 22
                            },
                            {
                                "metric": "SECURITY_POLICIES",
                                "limit": 10,
                                "usage": 8
                            },
                            {
                                "metric": "SECURITY_POLICY_RULES",
                                "limit": 100,
                                "usage": 80
                            },
                            {
                                "metric": "NETWORK_ENDPOINT_GROUPS",
                                "limit": 300,
                                "usage": 0
                            },
                            {
                                "metric": "INTERCONNECTS",
                                "limit": 6,
                                "usage": 0
                            },
                            {
                                "metric": "GLOBAL_INTERNAL_ADDRESSES",
                                "limit": 5000,
                                "usage": 1
                            },
                            {
                                "metric": "VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            },
                            {
                                "metric": "EXTERNAL_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/frost-forest-281330",
                        "defaultServiceAccount": "845005677082-compute@developer.gserviceaccount.com",
                        "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS",
                        "defaultNetworkTier": "PREMIUM"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the projects services are very close to the service limits', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The following services are over the 90%')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "compute#project",
                        "id": "2548647434039838416",
                        "creationTimestamp": "2019-06-19T11:00:31.059-07:00",
                        "name": "frost-forest-281330",
                        "commonInstanceMetadata": {
                            "kind": "compute#metadata",
                            "fingerprint": "bur0P6caU8Y="
                        },
                        "quotas": [
                            {
                                "metric": "SNAPSHOTS",
                                "limit": 5000,
                                "usage": 0
                            },
                            {
                                "metric": "NETWORKS",
                                "limit": 15,
                                "usage": 3
                            },
                            {
                                "metric": "FIREWALLS",
                                "limit": 200,
                                "usage": 3
                            },
                            {
                                "metric": "IMAGES",
                                "limit": 2000,
                                "usage": 1
                            },
                            {
                                "metric": "STATIC_ADDRESSES",
                                "limit": 21,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTES",
                                "limit": 250,
                                "usage": 63
                            },
                            {
                                "metric": "FORWARDING_RULES",
                                "limit": 45,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_POOLS",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "HEALTH_CHECKS",
                                "limit": 150,
                                "usage": 1
                            },
                            {
                                "metric": "IN_USE_ADDRESSES",
                                "limit": 69,
                                "usage": 2
                            },
                            {
                                "metric": "TARGET_INSTANCES",
                                "limit": 150,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTP_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "URL_MAPS",
                                "limit": 30,
                                "usage": 2
                            },
                            {
                                "metric": "BACKEND_SERVICES",
                                "limit": 9,
                                "usage": 1
                            },
                            {
                                "metric": "INSTANCE_TEMPLATES",
                                "limit": 300,
                                "usage": 1
                            },
                            {
                                "metric": "TARGET_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 0
                            },
                            {
                                "metric": "VPN_TUNNELS",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "BACKEND_BUCKETS",
                                "limit": 9,
                                "usage": 0
                            },
                            {
                                "metric": "ROUTERS",
                                "limit": 10,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_SSL_PROXIES",
                                "limit": 30,
                                "usage": 0
                            },
                            {
                                "metric": "TARGET_HTTPS_PROXIES",
                                "limit": 30,
                                "usage": 1
                            },
                            {
                                "metric": "SSL_CERTIFICATES",
                                "limit": 30,
                                "usage": 30
                            },
                            {
                                "metric": "SUBNETWORKS",
                                "limit": 175,
                                "usage": 167
                            },
                            {
                                "metric": "TARGET_TCP_PROXIES",
                                "limit": 30,
                                "usage": 28
                            },
                            {
                                "metric": "SECURITY_POLICIES",
                                "limit": 10,
                                "usage": 9
                            },
                            {
                                "metric": "SECURITY_POLICY_RULES",
                                "limit": 100,
                                "usage": 99
                            },
                            {
                                "metric": "NETWORK_ENDPOINT_GROUPS",
                                "limit": 300,
                                "usage": 0
                            },
                            {
                                "metric": "INTERCONNECTS",
                                "limit": 6,
                                "usage": 0
                            },
                            {
                                "metric": "GLOBAL_INTERNAL_ADDRESSES",
                                "limit": 5000,
                                "usage": 1
                            },
                            {
                                "metric": "VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 15
                            },
                            {
                                "metric": "EXTERNAL_VPN_GATEWAYS",
                                "limit": 15,
                                "usage": 14
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/frost-forest-281330",
                        "defaultServiceAccount": "845005677082-compute@developer.gserviceaccount.com",
                        "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS",
                        "defaultNetworkTier": "PREMIUM"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})  