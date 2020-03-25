var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./privateAccessEnabled');

const createCache = (err, data) => {
    return {
        subnetworks: {
            list: {
                'us-east1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('privateAccessEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a subnetwork error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query subnetworks')
                expect(results[0].region).to.equal('us-east1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no subnetwork records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No subnetworks present')
                expect(results[0].region).to.equal('us-east1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if the subnetwork has flow logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All Subnets in the Region have Private Google Access Enabled')
                expect(results[0].region).to.equal('us-east1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "enableFlowLogs" : true,
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
                        "creationTimestamp": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0",
                        "privateIpGoogleAccess": true
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the subnet does not have flow logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The following Subnets do not have Private Google Access Enabled')
                expect(results[0].region).to.equal('us-east1')
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
                        "creationTimestamp": "2019-02-28T18:19:38.677Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:33:E4:A0",
                        "privateIpGoogleAccess": false
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})