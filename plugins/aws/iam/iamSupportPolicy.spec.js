const expect = require('chai').expect;
var iamSupportPolicy = require('./iamSupportPolicy');

const listPolicies = [
    {
        PolicyName: "CloudTrailCloudwatchRole",
        PolicyId: "ANPAYE32SRU52MRBE7GDH",
        Arn: "arn:aws:iam::111111111111:policy/CloudTrailCloudwatchRole",
        Path: "/",
        DefaultVersionId: "v2",
        AttachmentCount: 0,
        PermissionsBoundaryUsageCount: 0,
        IsAttachable: true,
        CreateDate: "",
        UpdateDate: "",
        Tags: [],
    },
    {
        PolicyName: "AWSSupportAccess",
        PolicyId: "ANPAYE32SRU52MRBE7GDH",
        Arn: "arn:aws:iam::111111111111:policy/AWSSupportAccess",
        Path: "/",
        DefaultVersionId: "v2",
        AttachmentCount: 0,
        PermissionsBoundaryUsageCount: 0,
        IsAttachable: true,
        CreateDate: "",
        UpdateDate: "",
        Tags: [],
    },
    {
        PolicyName: "AWSSupportAccess",
        PolicyId: "ANPAYE32SRU52MRBE7GDH",
        Arn: "arn:aws:iam::111111111111:policy/AWSSupportAccess",
        Path: "/",
        DefaultVersionId: "v2",
        AttachmentCount: 1,
        PermissionsBoundaryUsageCount: 0,
        IsAttachable: true,
        CreateDate: "",
        UpdateDate: "",
        Tags: [],
    }
];

const createCache = (policies, entities) => {
    return {
        iam: {
            listPolicies: {
                "us-east-1": {
                    data: policies
                }

            }
        }
    }

}

const createNullCachePolicies = () => {
    return {
        iam: {
            listPolicies: {
                "us-east-1": {
                    data: null
                }
            },
        }
    }
}

const createNullCacheEntities = (policies) => {
    return {
        iam: {
            listPolicies: {
                "us-east-1": {
                    data: policies
                }

            }
        }
    }
}

describe('iamSupportPolicy',() =>{
    describe('run', () => {
        it('should PASS if no policy attachment to access support center',() => {
            const cache = createCache([listPolicies[2]]);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });

        it('should PASS if no policies',() => {
            const cache = createCache([]);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });
    
        it('should FAIL if no policy attachment to access support center',() => {
            const cache = createCache([listPolicies[0]]);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });

        it('should UNKNOWN if no policy returned',() => {
            const cache = createNullCachePolicies();
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
            });
        });
    })
})