var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./subnetMultiAd');

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
        }
    }
};

describe('multipleSubnets', function () {
    describe('run', function () {
        it('should give unknown result if a Subnet error is passed or no data is present', function (done) {
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
        it('should give passing result if no Subet records are found', function (done) {
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
        it('should give passing result if the subnet is multi AD', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The subnets in the VCN are regional')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "cidrBlock": "10.0.1.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaafnnevu3kpld76oriye2llmxexctk5b5p2bpclxbn655okva2h2la",
                        "displayName": "Public Subnet fMgC:US-ASHBURN-AD-2",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaaiordekrskkkddh7zhchrgvh72fv2tl4jt7zq3unrlc53dpi3jz5a",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": false,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaa6ihfuq4kr5i46rakq3uunbglbnlxnaoyt3u63xo4qmcdhjnbod4a",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma"
                        ],
                        "timeCreated": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the subnet is not multi AD', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('subnets in the VCN are not regional')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-2",
                        "cidrBlock": "10.0.1.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaafnnevu3kpld76oriye2llmxexctk5b5p2bpclxbn655okva2h2la",
                        "displayName": "Public Subnet fMgC:US-ASHBURN-AD-2",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaaiordekrskkkddh7zhchrgvh72fv2tl4jt7zq3unrlc53dpi3jz5a",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": false,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaa6ihfuq4kr5i46rakq3uunbglbnlxnaoyt3u63xo4qmcdhjnbod4a",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma"
                        ],
                        "timeCreated": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})