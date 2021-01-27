var expect = require('chai').expect;
const vpcPeeringConnections = require('./vpcPeeringConnections');

const listAccounts = [
    {
        "Id": "112233445566",
        "Arn": "arn:aws:organizations::112233445566:account/o-wd9d7dgznf/112233445566",
        "Email": "makhtar.pucit@gmail.com",
        "Name": "akhtar-practice",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-05T13:50:47.111000+05:00"
    },
    {
        "Id": "111122223333",
        "Arn": "arn:aws:organizations::112233445566:account/o-wd9d7dgznf/112233445566",
        "Email": "makhtar.pucit@gmail.com",
        "Name": "akhtar-practice",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-05T13:50:47.111000+05:00"
    }
];

const describeVpcPeeringConnections = [
    {
        "AccepterVpcInfo": {
            "OwnerId": "112233445566",
            "VpcId": "vpc-036273a23dcdba22f",
            "Region": "us-east-1"
        },
        "ExpirationTime": "2020-12-12T09:18:20+00:00",
        "RequesterVpcInfo": {
            "CidrBlock": "172.31.0.0/16",
            "CidrBlockSet": [
                {
                    "CidrBlock": "172.31.0.0/16"
                }
            ],
            "OwnerId": "111122223333",
            "PeeringOptions": {
                "AllowDnsResolutionFromRemoteVpc": false,
                "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                "AllowEgressFromLocalVpcToRemoteClassicLink": false
            },
            "VpcId": "vpc-99de2fe4",
            "Region": "us-east-1"
        },
        "Status": {
            "Code": "pending-acceptance",
            "Message": "Pending Acceptance by 111122223333"
        },
        "Tags": [
            {
                "Key": "Name",
                "Value": "ak-70"
            }
        ],
        "VpcPeeringConnectionId": "pcx-083996487133115e0"
    },
    {
        "AccepterVpcInfo": {
            "OwnerId": "000099998888",
            "VpcId": "vpc-036273a23dcdba22f",
            "Region": "us-east-1"
        },
        "ExpirationTime": "2020-12-12T09:18:20+00:00",
        "RequesterVpcInfo": {
            "CidrBlock": "172.31.0.0/16",
            "CidrBlockSet": [
                {
                    "CidrBlock": "172.31.0.0/16"
                }
            ],
            "OwnerId": "111122223333",
            "PeeringOptions": {
                "AllowDnsResolutionFromRemoteVpc": false,
                "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                "AllowEgressFromLocalVpcToRemoteClassicLink": false
            },
            "VpcId": "vpc-99de2fe4",
            "Region": "us-east-1"
        },
        "Status": {
            "Code": "pending-acceptance",
            "Message": "Pending Acceptance by 111122223333"
        },
        "Tags": [
            {
                "Key": "Name",
                "Value": "ak-70"
            }
        ],
        "VpcPeeringConnectionId": "pcx-083996487133115e0"
    }
];

const createCache = (organizationAccounts, vpcPeeringConnection) => {
    return {
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: organizationAccounts
                }
            }
        },
        ec2: {
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: vpcPeeringConnection
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        organizations: {
            listAccounts: {
                'us-east-1': {
                    err: {
                        message: 'error listing organization accounts'
                    },
                },
            },
        },
        ec2: {
            describeVpcPeeringConnections: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPC peering connections'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        organizations: {
            listAccounts: {
                'us-east-1': null,
            },
        },
        ec2: {
            describeVpcPeeringConnections: {
                'us-east-1': null,
            },
        },
    };
};


describe('vpcPeeringConnections', function () {
    describe('run', function () {
        it('should PASS if VPC peering connection does not allow communication outside organization accounts', function (done) {
            const cache = createCache(listAccounts, [describeVpcPeeringConnections[0]]);

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC peering connection allows communication outside organization accounts', function (done) {
            const cache = createCache(listAccounts, [describeVpcPeeringConnections[1]]);

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if No organization accounts found but VPC peering connection allows communication to accounts', function (done) {
            const cache = createCache([], [describeVpcPeeringConnections[1]]);

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPC peering connections found', function (done) {
            const cache = createCache([], []);

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list organization accounts', function (done) {
            const cache = createErrorCache();

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe VPC peering connections', function (done) {
            const cache = createCache([]);

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if not return anything if list organization accounts response is not found', function (done) {
            const cache = createNullCache();

            vpcPeeringConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
