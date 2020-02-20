var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./nfsPublicAccess');

const createCache = (err, data, mdata, sdata) => {
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
        exprt: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        mountTarget: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: mdata
                }
            }
        },
        subnet: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: sdata
                }
            }
        }
    }
};

describe('nfsPublicAccess', function () {
    describe('run', function () {
        it('should give passing result if an error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for file systems')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                undefined
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No file systems found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if there is public access on the File System', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The following NFS allow public access');
                expect(results[0].region).to.equal('us-ashburn-1');
                done()
            };

            const cache = createCache(
                null,
                [
                        {
                            "exportOptions": [
                                {
                                    "source": "0.0.0.0/0",
                                    "requirePrivilegedSourcePort": false,
                                    "access": "READ_WRITE",
                                    "identitySquash": "NONE",
                                    "anonymousUid": 65534,
                                    "anonymousGid": 65534
                                }
                            ],
                            "exportSetId": "ocid1.exportset.oc1.iad.aaaaaa4np2snjqnanfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "fileSystemId": "ocid1.filesystem.oc1.iad.aaaaaaaaaaaal26cnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "id": "ocid1.export.oc1.iad.aaaaacvippxgdr7nnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "lifecycleState": "ACTIVE",
                            "path": "/FileSystem-20190604-2257",
                            "timeCreated": "2019-06-04T22:57:46.291Z"
                        }
                    ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if there isnt public access on the File System', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('NFS does not allow public access');
                expect(results[0].region).to.equal('us-ashburn-1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "exportOptions": [
                            {
                                "source": "192.168.0.1/32",
                                "requirePrivilegedSourcePort": false,
                                "access": "READ_WRITE",
                                "identitySquash": "NONE",
                                "anonymousUid": 65534,
                                "anonymousGid": 65534
                            }
                        ],
                        "exportSetId": "ocid1.exportset.oc1.iad.aaaaaa4np2snjqnanfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "fileSystemId": "ocid1.filesystem.oc1.iad.aaaaaaaaaaaal26cnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "id": "ocid1.export.oc1.iad.aaaaacvippxgdr7nnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "lifecycleState": "ACTIVE",
                        "path": "/FileSystem-20190604-2257",
                        "timeCreated": "2019-06-04T22:57:46.291Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if there is public access on the File System but the subnet is private', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('NFS is in a private subnet and does not allow public access');
                expect(results[0].region).to.equal('us-ashburn-1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "exportOptions": [
                            {
                                "source": "0.0.0.0/0",
                                "requirePrivilegedSourcePort": false,
                                "access": "READ_WRITE",
                                "identitySquash": "NONE",
                                "anonymousUid": 65534,
                                "anonymousGid": 65534
                            }
                        ],
                        "exportSetId": "ocid1.exportset.oc1.iad.aaaaacvippxhznzjnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "fileSystemId": "ocid1.filesystem.oc1.iad.aaaaaaaaaaaal26cnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "id": "ocid1.export.oc1.iad.aaaaacvippxgdr7nnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "lifecycleState": "ACTIVE",
                        "path": "/FileSystem-20190604-2257",
                        "timeCreated": "2019-06-04T22:57:46.291Z"
                    }
                ],
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "privateSubnetMount",
                        "exportSetId": "ocid1.exportset.oc1.iad.aaaaacvippxhznzjnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "id": "ocid1.mounttarget.oc1.iad.aaaaacvippxhznzknfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "lifecycleState": "ACTIVE",
                        "privateIpIds": [
                            "ocid1.privateip.oc1.iad.aaaaaaaajzea4jjjjckmvehvd3h3ctrwq5wqn7uqdxnkpuxgjuxj2pdzhd3a"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaatheunvhfdmm72yortkxqydw6s4kvhzddyoj5nq5zvitcoyglkepa",
                        "nsgIds": [],
                        "timeCreated": "2020-01-13T23:02:25Z",
                        "freeformTags": {},
                        "definedTags": {}
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "MountTarget-20190604-2257",
                        "exportSetId": "ocid1.exportset.oc1.iad.aaaaaa4np2snjqnanfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "id": "ocid1.mounttarget.oc1.iad.aaaaaa4np2snjqnbnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "lifecycleState": "ACTIVE",
                        "privateIpIds": [
                            "ocid1.privateip.oc1.iad.abuwcljttcthvu6bimq7se5e23iknomb7rn2vf2vrfddnjfqvcvt6tu4clha"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaa7gwzgnac2rav2rsapkkogspt6vsgrb6imav44jgu3h5xyef3zrgq",
                        "nsgIds": [],
                        "timeCreated": "2019-06-04T22:57:40Z",
                        "freeformTags": {},
                        "definedTags": {}
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
                        "cidrBlock": "10.0.100.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4xhwhj6zip45qg7bv7cpb5kop23wuii6ymlmkloulpnxw4d6lsra",
                        "displayName": "private subnet",
                        "dnsLabel": "privatesubnet",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaatheunvhfdmm72yortkxqydw6s4kvhzddyoj5nq5zvitcoyglkepa",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": true,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaags5xhytolz3wasw6u6ca7kcvlvksvnikljhd4klo6nftsvymabeq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq"
                        ],
                        "subnetDomainName": "privatesubnet.giovcntest1.oraclevcn.com",
                        "timeCreated": "2019-09-11T21:13:27.646Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra",
                        "virtualRouterIp": "10.0.100.1",
                        "virtualRouterMac": "00:00:17:C9:86:27"
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-3",
                        "cidrBlock": "10.0.2.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4xhwhj6zip45qg7bv7cpb5kop23wuii6ymlmkloulpnxw4d6lsra",
                        "displayName": "Public Subnet fMgC:US-ASHBURN-AD-3",
                        "dnsLabel": "sub08061941232",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaa3uqtt3qsqflm2svdwczecz3t4kljxtbh63itdfvyniyaujhfewdq",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": false,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaags5xhytolz3wasw6u6ca7kcvlvksvnikljhd4klo6nftsvymabeq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq"
                        ],
                        "subnetDomainName": "sub08061941232.giovcntest1.oraclevcn.com",
                        "timeCreated": "2019-08-06T19:41:26.019Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra",
                        "virtualRouterIp": "10.0.2.1",
                        "virtualRouterMac": "00:00:17:C9:86:27"
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-2",
                        "cidrBlock": "10.0.1.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4xhwhj6zip45qg7bv7cpb5kop23wuii6ymlmkloulpnxw4d6lsra",
                        "displayName": "Public Subnet fMgC:US-ASHBURN-AD-2",
                        "dnsLabel": "sub08061941231",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaakzfsgrf7ct2roqc2em3duvoqoecfnhvbqtjdlr27suoc7yrf63tq",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": false,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaags5xhytolz3wasw6u6ca7kcvlvksvnikljhd4klo6nftsvymabeq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq"
                        ],
                        "subnetDomainName": "sub08061941231.giovcntest1.oraclevcn.com",
                        "timeCreated": "2019-08-06T19:41:25.588Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:C9:86:27"
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "cidrBlock": "10.0.0.0/24",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "dhcpOptionsId": "ocid1.dhcpoptions.oc1.iad.aaaaaaaa4xhwhj6zip45qg7bv7cpb5kop23wuii6ymlmkloulpnxw4d6lsra",
                        "displayName": "Public Subnet fMgC:US-ASHBURN-AD-1",
                        "dnsLabel": "sub08061941230",
                        "freeformTags": {},
                        "id": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "lifecycleState": "AVAILABLE",
                        "prohibitPublicIpOnVnic": false,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaags5xhytolz3wasw6u6ca7kcvlvksvnikljhd4klo6nftsvymabeq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq"
                        ],
                        "subnetDomainName": "sub08061941230.giovcntest1.oraclevcn.com",
                        "timeCreated": "2019-08-06T19:41:25.219Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra",
                        "virtualRouterIp": "10.0.0.1",
                        "virtualRouterMac": "00:00:17:C9:86:27"
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
    })
})