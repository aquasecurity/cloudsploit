
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
        it('should PASS if all Workspaces count is upto the recommended threshold i.e. 50', function (done) {
            const cache = createCache([describeWorkspaces[0]]);
            workspacesInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Workspaces count is greater than the recommended threshold', function (done) {
            const cache = createCache(Array(51).fill(describeWorkspaces[0]));
            workspacesInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
