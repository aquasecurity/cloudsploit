var expect = require('chai').expect;
const notebookInstanceInVpc = require('./notebookInstanceInVpc');

const listNotebookInstances = [
    {
        "NotebookInstanceName": "nb-instance-2",
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:112233445566:notebook-instance/nb-instance-2",
        "NotebookInstanceStatus": "InService",
        "Url": "nb-instance-2.notebook.us-east-1.sagemaker.aws",
        "KmsKeyId": "0723d7e2-8655-4553-b4e3-20084f6bddba",
        "InstanceType": "ml.t2.medium",
        "CreationTime": "2020-11-16T14:59:14.821Z",
        "LastModifiedTime": "2020-11-16T14:59:21.692Z",      
    },
    {
        "NotebookInstanceName": "nb-instance-3",
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:112233445566:notebook-instance/nb-instance-3",
        "NotebookInstanceStatus": "InService",
        "DirectInternetAccess": "Enabled",
        "Url": "nb-instance-2.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t2.medium",
    }
];

const describeNotebookInstance = [
    {
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:1122334455:notebook-instance/test",
        "NotebookInstanceName": "test",
        "NotebookInstanceStatus": "Pending",
        "Url": "test-mdbp.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t3.medium",
        "SubnetId": "subnet-090543c3cc7bee455",
        "SecurityGroups": [
            "sg-0931c3a02deed68f5"
        ],
        "RoleArn": "arn:aws:iam::11222333445:role/service-role/AmazonSageMaker-ExecutionRole-20230803T155360",
        "NetworkInterfaceId": "eni-0fce758c1693daae7",
        "LastModifiedTime": "2023-08-04T12:59:53.661000+05:00",
        "CreationTime": "2023-08-04T12:59:46.521000+05:00",
        "DirectInternetAccess": "Disabled",
        "VolumeSizeInGB": 5,
        "RootAccess": "Enabled",
        "PlatformIdentifier": "notebook-al2-v2",
        "InstanceMetadataServiceConfiguration": {
            "MinimumInstanceMetadataServiceVersion": "2"
        }
    },
    {
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:11222334455:notebook-instance/test",
        "NotebookInstanceName": "test",
        "NotebookInstanceStatus": "Pending",
        "Url": "test-mdbp.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t3.medium",
        "SecurityGroups": [
            "sg-0931c3a02deed68f5"
        ],
        "RoleArn": "arn:aws:iam::1122334455:role/service-role/AmazonSageMaker-ExecutionRole-20230803T155360",
        "LastModifiedTime": "2023-08-04T12:59:53.661000+05:00",
        "CreationTime": "2023-08-04T12:59:46.521000+05:00",
        "DirectInternetAccess": "Disabled",
        "VolumeSizeInGB": 5,
        "RootAccess": "Enabled",
        "PlatformIdentifier": "notebook-al2-v2",
        "InstanceMetadataServiceConfiguration": {
            "MinimumInstanceMetadataServiceVersion": "2"
        }
    }


];

const createCache = (listInstances, instances) => {
    var name = (listInstances && listInstances.length) ? listInstances[0].NotebookInstanceName : null;
    return {
        sagemaker: {
            listNotebookInstances: {
                'us-east-1': {
                    data: listInstances
                }
            },
            describeNotebookInstance: {
                'us-east-1': {
                    [name] : {
                        data: instances
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        sagemaker: {
            listNotebookInstances: {
                'us-east-1': {
                    err: {
                        message: 'Error listing notebook instances'
                    }
                }
            },
            describeNotebookInstance: {
                'us-east-1': {
                    'NotebookInstanceName': {
                        err: {
                            message: 'error fetching instance detail'
                        },
                    },
                },
            }
        }
    };
};

const createNullCache = () => {
    return {
        sagemaker: {
            listNotebookInstances: {
                'us-east-1': null
            }
        }
    };
};


describe('notebookInstanceInVpc', function() {
    describe('run', function () {
        it('should PASS if instance launched within VPC', function(done) {
            const cache = createCache([listNotebookInstances[0]],describeNotebookInstance[0]);
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance is not launched within VPC', function(done) {
            const cache = createCache([listNotebookInstances[1]],describeNotebookInstance[1]);
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Notebook instances found', function (done) {
            const cache = createCache([]);
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Notebook instances', function (done) {
            const cache = createErrorCache();
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Notebook instances response not found', function (done) {
            const cache = createNullCache();
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
