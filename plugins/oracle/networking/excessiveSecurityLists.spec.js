var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./excessiveSecurityLists');

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

        securityList: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('excessiveSecurityLists', function () {
    describe('run', function () {
        it('should give unknown result if a security list error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no security list records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security lists found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if security lists have an acceptable amount of lists', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Acceptable number of security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give warning result if security lists have an large amount of lists', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('Large number of security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if security lists have an excessive amount of lists', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Excessive number of security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for giovcntest1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-08-06T19:41:23.731Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network #1",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.0.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:24:37.604Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q"
                    },
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "Default Security List for Test Virtual Network 2",
                        "egressSecurityRules": [
                            {
                                "destination": "0.0.0.0/0",
                                "destinationType": "CIDR_BLOCK",
                                "isStateless": false,
                                "protocol": "all"
                            }
                        ],
                        "freeformTags": {},
                        "id": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
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
                            },
                            {
                                "icmpOptions": {
                                    "code": 4,
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "0.0.0.0/0",
                                "sourceType": "CIDR_BLOCK"
                            },
                            {
                                "icmpOptions": {
                                    "type": 3
                                },
                                "isStateless": false,
                                "protocol": "1",
                                "source": "10.1.0.0/16",
                                "sourceType": "CIDR_BLOCK"
                            }
                        ],
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-06-04T18:32:32.614Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq"
                    },
                ]

            );

            plugin.run(cache, {}, callback);
        })
    })
})