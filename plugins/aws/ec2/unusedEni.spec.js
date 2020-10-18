var expect = require('chai').expect;
const unusedEni = require('./unusedEni');

const describeNetworkInterfaces = [
    {
        "Attachment": {
            "AttachTime": "2020-10-14T22:57:33.000Z",
            "AttachmentId": "eni-attach-0aa55688e0a7acc05",
            "DeleteOnTermination": true,
            "DeviceIndex": 0,
            "InstanceId": "i-02cd6ecf4fb6f634d",
            "InstanceOwnerId": "112233445566",
            "Status": "attached"
        },
        "AvailabilityZone": "us-east-1e",
        "Description": "",
        "InterfaceType": "interface",
        "Ipv6Addresses": [],
        "MacAddress": "06:77:f1:13:ed:e3",
        "NetworkInterfaceId": "eni-0984f74e07528ea22",
        "OwnerId": "112233445566",
        "Status": "in-use"
    },
    {
        "Association": {
            "IpOwnerId": "amazon-elb",
            "PublicDnsName": "ec2-52-44-135-154.compute-1.amazonaws.com",
            "PublicIp": "52.44.135.154"
        },
        "Attachment": {
            "AttachTime": "2020-10-24T05:21:37.000Z",
            "AttachmentId": "eni-attach-05ba877d1ad0030a5",
            "DeleteOnTermination": false,
            "DeviceIndex": 1,
            "InstanceOwnerId": "amazon-elb",
            "Status": "attached"
        },
        "AvailabilityZone": "us-east-1b",
        "InterfaceType": "interface",
        "Ipv6Addresses": [],
        "MacAddress": "12:07:6f:a1:5b:bf",
        "NetworkInterfaceId": "eni-0f8fe766438d3a131",
        "OwnerId": "112233445566",
        "Status": "available",
    }
];

const createCache = (eni) => {
    return {
        ec2:{
            describeNetworkInterfaces: {
                'us-east-1': {
                    data: eni
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeNetworkInterfaces: {
                'us-east-1': {
                    err: {
                        message: 'error describing AWS Elastic Network Interfaces'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeNetworkInterfaces: {
                'us-east-1': null,
            },
        },
    };
};

describe('unusedEni', function () {
    describe('run', function () {
        it('should PASS if AWS ENI is in use', function (done) {
            const cache = createCache([describeNetworkInterfaces[0]]);
            unusedEni.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWS ENI is not in use', function (done) {
            const cache = createCache([describeNetworkInterfaces[1]]);
            unusedEni.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no AWS ENIs found', function (done) {
            const cache = createCache([]);
            unusedEni.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe AWS ENIs', function (done) {
            const cache = createErrorCache();
            unusedEni.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe network interfaces response not found', function (done) {
            const cache = createNullCache();
            unusedEni.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
