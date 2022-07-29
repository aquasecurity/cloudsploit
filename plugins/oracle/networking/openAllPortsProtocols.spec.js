var expect = require('chai').expect;
const plugin = require('./openAllPortsProtocols');

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
                "protocol": "all",
                "source": "0.0.0.0/0",
                "sourceType": "CIDR_BLOCK"
            }
        ],
        "lifecycleState": "AVAILABLE",
        "timeCreated": "2022-04-17T01:16:32.366Z",
        "vcnId": "vcn1"
    },
    {
        "compartmentId": "compartment-1",
        "displayName": "list2",
        "egressSecurityRules": [
            {
                "destination": "0.0.0.0/0",
                "destinationType": "CIDR_BLOCK",
                "isStateless": false,
                "protocol": "all"
            }
        ],
        "freeformTags": {},
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
            },
        ],
        "lifecycleState": "AVAILABLE",
        "timeCreated": "2022-01-09T13:02:20.425Z",
        "vcnId": "vcn1"
    }
];

const vcnData = [
    {
        
        "compartmentId": "compartment1",
        "displayName": "vcn1",
        "freeformTags": {},
        "id": "vcn1",
        "lifecycleState": "AVAILABLE",
        "timeCreated": "2022-01-09T13:02:20.425Z"
    }
]
const createCache = (listsData, listsErr, vcnData, vcnErr) => {
    return {
        vcn: {
            list: {
                "us-ashburn-1": {
                    data: vcnData,
                    err: vcnErr
                }
            }
        },
        securityList: {
            list: {
                "us-ashburn-1": {
                    data: listsData,
                    err: listsErr
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



describe('openAllPortsProtocols', function () {
    describe('run', function () {
        it('should give unknown if unable to query for VCNs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for VCNs')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

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
                vcnData,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should PASS if no security lists are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security lists found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                null,
                vcnData,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should PASS if no open ports found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[1]],
                null,
                vcnData,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should FAIL if security list has all ports open to public', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [securityLists[0]],
                null,
                vcnData,
                null
            );

            plugin.run(cache, {}, callback);
        });
    });
});
