var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./multipleSubnets');

const createCache = (vcnErr, subnetErr, vcnData, subnetData) => {
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
        vcn: {
            list: {
                "us-ashburn-1": {
                    data: vcnData,
                    err: vcnErr
                }
            }
        },
        subnet: {
            list: {
                "us-ashburn-1": {
                    data: subnetData,
                    err: subnetErr
                }
            }
        }
    }
};

describe('multipleSubnets', function () {
    describe('run', function () {
        it('should give unknown result if a VCN error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for VCNs')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
                null,
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no VCN records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No VCNs found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                [],
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give unknown result if a Subnet error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for subnets')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                ['hello', 'hi'],

                    [
                        {
                            "cidrBlock": "10.1.0.0/16",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "defaultDhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaaxh7iyslywylxkgniny66a4plra33abpyg5y2lpqcutgfyneouj2a",
                            "defaultRouteTableId": "ocid1.routetable.oc1.iad.aaaaaaaavfrldnlzxwbvdikxybzunzzgjgeq43upwzfa5whjtrndoqidm7lq",
                            "defaultSecurityListId": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
                            "definedTags": {},
                            "displayName": "Test Virtual Network 2",
                            "dnsLabel": "testvirtualnetw",
                            "freeformTags": {},
                            "id": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq",
                            "lifecycleState": "AVAILABLE",
                            "timeCreated": "2019-06-04T18:32:32.614Z",
                            "vcnDomainName": "testvirtualnetw.oraclevcn.com"
                        }
                    ],
            null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give warning result if there are no subnets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('The VCN does not have any subnets')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                [
                        {
                            "cidrBlock": "10.1.0.0/16",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "defaultDhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaaxh7iyslywylxkgniny66a4plra33abpyg5y2lpqcutgfyneouj2a",
                            "defaultRouteTableId": "ocid1.routetable.oc1.iad.aaaaaaaavfrldnlzxwbvdikxybzunzzgjgeq43upwzfa5whjtrndoqidm7lq",
                            "defaultSecurityListId": "ocid1.securitylist.oc1.iad.aaaaaaaaptqi7soqbtr6uaskgtyc2qjivca3a3ux5s5u4iyhcyx3d66wya6a",
                            "definedTags": {},
                            "displayName": "Test Virtual Network 2",
                            "dnsLabel": "testvirtualnetw",
                            "freeformTags": {},
                            "id": "ocid1.vcn.oc1.iad.aaaaaaaaeipubpvwvbxo4wse2wh7e3subl65dfv2rlmpczadbluneqg2ntlq",
                            "lifecycleState": "AVAILABLE",
                            "timeCreated": "2019-06-04T18:32:32.614Z",
                            "vcnDomainName": "testvirtualnetw.oraclevcn.com"
                        }
                    ],
                ['hello world']
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if there are multiple subnets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('different subnets in VCN')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                [
                        {
                            "cidrBlock": "10.0.0.0/16",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "defaultDhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4ytfmktadjazpa6o4ponigkha5qmydkxrac6vcirdshejakxwmnq",
                            "defaultRouteTableId": "ocid1.routetable.oc1.iad.aaaaaaaayqkxq4lotwh7vzorhkcc2tdv5jnt5z464hnbaijfwjsolpmnctiq",
                            "defaultSecurityListId": "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq",
                            "definedTags": {},
                            "displayName": "Test Virtual Network #1",
                            "freeformTags": {},
                            "id": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q",
                            "lifecycleState": "AVAILABLE",
                            "timeCreated": "2019-02-28T18:24:37.604Z"
                        },

                    ],
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
                        },
                        {
                            "availabilityDomain": "fMgC:US-ASHBURN-AD-3",
                            "cidrBlock": "10.0.2.0/24",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "definedTags": {},
                            "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaafnnevu3kpld76oriye2llmxexctk5b5p2bpclxbn655okva2h2la",
                            "displayName": "Public Subnet fMgC:US-ASHBURN-AD-3",
                            "freeformTags": {},
                            "id": "ocid1.subnet.oc1.iad.aaaaaaaax54dso24tva2lmhyeqd7djd2z5pv5r22t4ib3adhthow6pqg652q",
                            "lifecycleState": "AVAILABLE",
                            "prohibitPublicIpOnVnic": false,
                            "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaa6ihfuq4kr5i46rakq3uunbglbnlxnaoyt3u63xo4qmcdhjnbod4a",
                            "securityListIds": [
                                "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma"
                            ],
                            "timeCreated": "2019-02-28T18:19:38.559Z",
                            "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                            "virtualRouterIp": "10.0.2.1",
                            "virtualRouterMac": "00:00:17:33:E4:A0"
                        },
                        {
                            "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                            "cidrBlock": "10.0.0.0/24",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "definedTags": {},
                            "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaafnnevu3kpld76oriye2llmxexctk5b5p2bpclxbn655okva2h2la",
                            "displayName": "Public Subnet fMgC:US-ASHBURN-AD-1",
                            "freeformTags": {},
                            "id": "ocid1.subnet.oc1.iad.aaaaaaaaebijfibsowmrjqyegn74qtqv5iiuflihlqw6sz23pm4h4jbj2fhq",
                            "lifecycleState": "AVAILABLE",
                            "prohibitPublicIpOnVnic": false,
                            "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaa6ihfuq4kr5i46rakq3uunbglbnlxnaoyt3u63xo4qmcdhjnbod4a",
                            "securityListIds": [
                                "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma"
                            ],
                            "timeCreated": "2019-02-28T18:19:38.155Z",
                            "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                            "virtualRouterIp": "10.0.0.1",
                            "virtualRouterMac": "00:00:17:33:E4:A0"
                        },
                        {
                            "availabilityDomain": "fMgC:US-ASHBURN-AD-3",
                            "cidrBlock": "10.0.2.0/24",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "definedTags": {},
                            "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4ytfmktadjazpa6o4ponigkha5qmydkxrac6vcirdshejakxwmnq",
                            "displayName": "Public Subnet fMgC:US-ASHBURN-AD-3",
                            "freeformTags": {},
                            "id": "ocid1.subnet.oc1.iad.aaaaaaaanavnofrpoc3hvdccq65vx5h7vrlyydxbhwepcxuio2zist7hl7da",
                            "lifecycleState": "AVAILABLE",
                            "prohibitPublicIpOnVnic": false,
                            "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaayqkxq4lotwh7vzorhkcc2tdv5jnt5z464hnbaijfwjsolpmnctiq",
                            "securityListIds": [
                                "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq"
                            ],
                            "timeCreated": "2019-02-28T18:24:42.955Z",
                            "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q",
                            "virtualRouterIp": "10.0.2.1",
                            "virtualRouterMac": "00:00:17:2D:79:5A"
                        },
                        {
                            "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                            "cidrBlock": "10.0.0.0/24",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "definedTags": {},
                            "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4ytfmktadjazpa6o4ponigkha5qmydkxrac6vcirdshejakxwmnq",
                            "displayName": "Public Subnet fMgC:US-ASHBURN-AD-1",
                            "freeformTags": {},
                            "id": "ocid1.subnet.oc1.iad.aaaaaaaa7gwzgnac2rav2rsapkkogspt6vsgrb6imav44jgu3h5xyef3zrgq",
                            "lifecycleState": "AVAILABLE",
                            "prohibitPublicIpOnVnic": false,
                            "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaayqkxq4lotwh7vzorhkcc2tdv5jnt5z464hnbaijfwjsolpmnctiq",
                            "securityListIds": [
                                "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq"
                            ],
                            "timeCreated": "2019-02-28T18:24:42.487Z",
                            "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q",
                            "virtualRouterIp": "10.0.0.1",
                            "virtualRouterMac": "00:00:17:2D:79:5A"
                        },
                        {
                            "availabilityDomain": "fMgC:US-ASHBURN-AD-2",
                            "cidrBlock": "10.0.1.0/24",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                            "definedTags": {},
                            "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4ytfmktadjazpa6o4ponigkha5qmydkxrac6vcirdshejakxwmnq",
                            "displayName": "Public Subnet fMgC:US-ASHBURN-AD-2",
                            "freeformTags": {},
                            "id": "ocid1.subnet.oc1.iad.aaaaaaaa26udyigjfkmw5idc5qoqht4nyeyiontctuml6ruzsgk3scoxgsya",
                            "lifecycleState": "AVAILABLE",
                            "prohibitPublicIpOnVnic": false,
                            "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaayqkxq4lotwh7vzorhkcc2tdv5jnt5z464hnbaijfwjsolpmnctiq",
                            "securityListIds": [
                                "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq"
                            ],
                            "timeCreated": "2019-02-28T18:24:42.157Z",
                            "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q",
                            "virtualRouterIp": "10.0.1.1",
                            "virtualRouterMac": "00:00:17:2D:79:5A"
                        }
                    ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if theres only 1 subnet in a vpc', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Only one subnet is used.')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                [
                    {
                        "cidrBlock": "10.0.0.0/16",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "defaultDhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaafnnevu3kpld76oriye2llmxexctk5b5p2bpclxbn655okva2h2la",
                        "defaultRouteTableId": "ocid1.routetable.oc1.iad.aaaaaaaa6ihfuq4kr5i46rakq3uunbglbnlxnaoyt3u63xo4qmcdhjnbod4a",
                        "defaultSecurityListId": "ocid1.securitylist.oc1.iad.aaaaaaaazhtqkhrkifh7h2jherpmogcofcfvs2i6aeaqnzdueyhhxwjgrlma",
                        "definedTags": {},
                        "displayName": "Test Virtual Network #1",
                        "freeformTags": {},
                        "id": "ocid1.vcn.oc1.iad.aaaaaaaaihl7n5qajssmue7fse6g2wkmtsbihpad7rhqcxqwnuu5sriv3wfq",
                        "lifecycleState": "AVAILABLE",
                        "timeCreated": "2019-02-28T18:19:32.594Z"
                    }
                ],
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