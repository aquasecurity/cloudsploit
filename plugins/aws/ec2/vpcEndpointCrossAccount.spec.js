var expect = require('chai').expect;
const vpcEndpointCrossAccount = require('./vpcEndpointCrossAccount');

const describeVpcEndpoints = [
    {
        "VpcEndpointId": "vpce-0cabb01596dba926e",
        "VpcEndpointType": "Interface",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.lambda",
        "State": "available",
        "PolicyDocument": "{\n    \"Id\": \"Policy1607050387464\",\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": {\n                \"AWS\": [\n                    \"arn:aws:iam::111222333444:root\",\n                    \"arn:aws:iam::111222333444:root\"\n                ]\n            }\n        }\n    ]\n}","RouteTableIds": [],
        "SubnetIds": [],
        "Groups": [],
        "PrivateDnsEnabled": true,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [],
        "DnsEntries": [],
        "CreationTimestamp": "2020-12-04T02:26:34.761000+00:00",
        "Tags": [],
        "OwnerId": "11112222333"
    },
    {
        "VpcEndpointId": "vpce-0cabb01596dba926e",
        "VpcEndpointType": "Interface",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.lambda",
        "State": "available",
        "PolicyDocument": "{\n    \"Id\": \"Policy1607050387464\",\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": {\n                \"AWS\": [\n                    \"arn:aws:sts::111122223333:root\"\n                ]\n            }\n        },\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": {\n                \"AWS\": [\n                    \"arn:aws:iam::111122223333:root\",\n                    \"arn:aws:iam::111122223333:root\"\n                ]\n            }\n        },\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": {\n                \"AWS\": \"*\"\n            }\n        },\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": \"*\"\n        }\n    ]\n}",
        "RouteTableIds": [],
        "SubnetIds": [],
        "Groups": [],
        "PrivateDnsEnabled": true,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [],
        "DnsEntries": [],
        "CreationTimestamp": "2020-12-04T02:26:34.761000+00:00",
        "Tags": [],
        "OwnerId": "11112222333"
    },
    {
        "VpcEndpointId": "vpce-0cabb01596dba926e",
        "VpcEndpointType": "Interface",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.lambda",
        "State": "available",
        "PolicyDocument": "{\n    \"Id\": \"Policy1607050387464\",\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"Stmt1607050377913\",\n            \"Action\": \"s3:*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"arn:aws:s3:::testingparquet\",\n            \"Principal\": {\n                \"AWS\": [\n                   \"arn:aws:iam::11112222333:root\",\n                ]\n            }\n        },\n        ]\n}",
        "RouteTableIds": [],
        "SubnetIds": [],
        "Groups": [],
        "PrivateDnsEnabled": true,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [],
        "DnsEntries": [],
        "CreationTimestamp": "2020-12-04T02:26:34.761000+00:00",
        "Tags": [],
        "OwnerId": "111122223333"
    },
];

const createCache = (vpcEndpoints) => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    data: vpcEndpoints
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111222333444'
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPC endpoints'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': null,
            },
        },
    };
};

describe('vpcEndpointCrossAccount', function () {
    describe('run', function () {
        it('should PASS if VPC endpoint does not allow cross account access', function (done) {
            const cache = createCache([describeVpcEndpoints[0]]);
            const settings = { vpc_trusted_cross_account_arns: 'arn:aws:iam::11112222333:root' };

            vpcEndpointCrossAccount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC endpoint allows cross account access', function (done) {
            const cache = createCache([describeVpcEndpoints[1]]);
            const settings = { vpc_trusted_cross_account_arns: '111122223333' };

            vpcEndpointCrossAccount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPC endpoints found', function (done) {
            const cache = createCache([]);
            vpcEndpointCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for VPC endpoints', function (done) {
            const cache = createErrorCache();
            vpcEndpointCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results describe VPC endpoints response not found', function (done) {
            const cache = createNullCache();
            vpcEndpointCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
