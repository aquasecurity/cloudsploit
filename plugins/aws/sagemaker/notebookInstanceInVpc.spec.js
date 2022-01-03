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
        "SubnetId": "subnet-012345678",
        "NetworkInterfaceId": "eni-0123456789abcdef0"
    },
    {
        "NotebookInstanceName": "nb-instance-3",
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:112233445566:notebook-instance/nb-instance-3",
        "NotebookInstanceStatus": "InService",
        "DirectInternetAccess": "Enabled",
        "Url": "nb-instance-2.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t2.medium",
        "CreationTime": "2020-11-16T14:59:14.821Z",
        "LastModifiedTime": "2020-11-16T14:59:21.692Z"
    }
];

const createCache = (instances) => {
    return {
        sagemaker: {
            listNotebookInstances: {
                'us-east-1': {
                    data: instances
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
            const cache = createCache([listNotebookInstances[0]]);
            notebookInstanceInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance is not launched within VPC', function(done) {
            const cache = createCache([listNotebookInstances[1]]);
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
