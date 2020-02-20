var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dbPrivateSubnetOnly');

const createCache = (err, data, sdata, serr) => {
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
        dbSystem: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        subnet: {
            list: {
                'us-ashburn-1': {
                    err: serr,
                    data: sdata
                }
            }
        }
    }
};

describe('dbPrivateSubnetOnly', function () {
    describe('run', function () {
        it('should give unknown result if a db system error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for database systems:')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['hello'],
                undefined
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if a subnet error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for subnets:')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                ['hello'],
                undefined,
                ['hello']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no subnets or db systems are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No database systems or subnets present')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

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
                ['hello'],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no db systems are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No database systems found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
                ['data'],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if database systems are in public subnets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The following db systems use the public subnet')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-1"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7a36nmivltthuqvwlbkkycv7rf7h75sjdziuym5vdqkjwo5hje4q",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": "Hostname oraclehello is already in-use in this subnet ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq. Please terminate & re-provision the instance with a non-overlapping hostname.",
                        "lifecycleState": "TERMINATED",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": null,
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:40.542Z",
                        "timeZone": "UTC",
                        "version": null,
                        "vipIds": null
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-3"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7lonqrgxsl653pvr5hpbyms5ptvmv653sgvqvxdxo7qjhvnpn2ga",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": null,
                        "lifecycleState": "AVAILABLE",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": "ocid1.vcndnsrecord.oc1.iad.abuwcljtvbjvzkqlfsgc4ig2cbybfz7wamzy274rs6otkdlelnvwnzz2tk5a",
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:39.153Z",
                        "timeZone": "UTC",
                        "version": "18.6.0.0.190416",
                        "vipIds": null
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
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if database systems are in private subnets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All db systems are in private subnets')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-1"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7a36nmivltthuqvwlbkkycv7rf7h75sjdziuym5vdqkjwo5hje4q",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": "Hostname oraclehello is already in-use in this subnet ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq. Please terminate & re-provision the instance with a non-overlapping hostname.",
                        "lifecycleState": "TERMINATED",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": null,
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:40.542Z",
                        "timeZone": "UTC",
                        "version": null,
                        "vipIds": null
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-3"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7lonqrgxsl653pvr5hpbyms5ptvmv653sgvqvxdxo7qjhvnpn2ga",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": null,
                        "lifecycleState": "AVAILABLE",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": "ocid1.vcndnsrecord.oc1.iad.abuwcljtvbjvzkqlfsgc4ig2cbybfz7wamzy274rs6otkdlelnvwnzz2tk5a",
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:39.153Z",
                        "timeZone": "UTC",
                        "version": "18.6.0.0.190416",
                        "vipIds": null
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaayqkxq4lotwh7vzorhkcc2tdv5jnt5z464hnbaijfwjsolpmnctiq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaai3cwmosnfihr4rxpeyjfbt7j522tdoexvr2fyr6kqioxhdwwfyzq"
                        ],
                        "timeCreated": "2019-02-28T18:24:42.157Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaakw2ep6iemb6wy3pexoox63rjpqlnyjinzdoyewee7e22zhrbqp7q",
                        "virtualRouterIp": "10.0.1.1",
                        "virtualRouterMac": "00:00:17:2D:79:5A"
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
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
                        "prohibitPublicIpOnVnic": true,
                        "routeTableId": "ocid1.routetable.oc1.iad.aaaaaaaags5xhytolz3wasw6u6ca7kcvlvksvnikljhd4klo6nftsvymabeq",
                        "securityListIds": [
                            "ocid1.securitylist.oc1.iad.aaaaaaaatrwtteamnooxc5uiv5vxm4pt6srxmndbgompt46xvvahfxmj2nfq"
                        ],
                        "subnetDomainName": "sub08061941230.giovcntest1.oraclevcn.com",
                        "timeCreated": "2019-08-06T19:41:25.219Z",
                        "vcnId": "ocid1.vcn.oc1.iad.aaaaaaaa5irgqmsbonndgikthiruk3porpadlpojbd5saooulz4mcf7gdfra",
                        "virtualRouterIp": "10.0.0.1",
                        "virtualRouterMac": "00:00:17:C9:86:27"
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        });
    });
});