
var expect = require('chai').expect;
var workspacesInstanceCount = require('./workspacesInstanceCount.js');

const describeWorkspaces = [
    {
        WorkspaceId: 'ws-f7hsrphp6',
        DirectoryId: 'd-9067552532',
        UserName: 'test',
        IpAddress: '172.16.1.134',
        State: 'AVAILABLE',
        BundleId: 'wsb-clj85qzj1',
        SubnetId: 'subnet-017fd5eda595ac73f',
        ComputerName: 'test',
        WorkspaceProperties: {
            RunningMode: 'AUTO_STOP',
            RunningModeAutoStopTimeoutInMinutes: 60,
            RootVolumeSizeGib: 80,
            UserVolumeSizeGib: 50,
            ComputeTypeName: 'STANDARD'
        },
        ModificationStates: []
    },
    {
        WorkspaceId: 'ws-f7hsrphp6',
        DirectoryId: 'd-9067552532',
        UserName: 'test',
        IpAddress: '172.16.1.134',
        State: 'AVAILABLE',
        BundleId: 'wsb-clj85qzj1',
        SubnetId: 'subnet-017fd5eda595ac73f',
        ComputerName: 'test',
        WorkspaceProperties: {
            RunningMode: 'AUTO_STOP',
            RunningModeAutoStopTimeoutInMinutes: 60,
            RootVolumeSizeGib: 80,
            UserVolumeSizeGib: 50,
            ComputeTypeName: 'PERFORMANCE'
        },
        ModificationStates: []
    },
];

const createCache = (data, err) => {
    return {
        workspaces: {
          describeWorkspaces: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            }
        }
    };
};

describe('workspacesInstanceCount', function () {
    describe('run', function () {
        it('should PASS if all Workspaces count is upto the desired threshold i.e. 10', function (done) {
            const cache = createCache([describeWorkspaces[0]]);
            workspacesInstanceCount.run(cache, { workspace_instance_limit: 10 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WorkSpaces Instance count is 1 of 10 desired threshold');
                done();
            });
        });

        it('should FAIL if Workspaces count is greater than the desired threshold', function (done) {
            const cache = createCache(Array(3).fill(describeWorkspaces[0]));
            workspacesInstanceCount.run(cache, { workspace_instance_limit: 2 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WorkSpaces Instance count is 3 of 2 desired threshold');
                done();
            });
        });

        it('should PASS if no WorkSpaces instances found', function (done) {
            const cache = createCache([]);
            workspacesInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
