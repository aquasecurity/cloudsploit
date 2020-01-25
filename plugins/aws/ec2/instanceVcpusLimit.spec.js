var assert = require('assert');
var expect = require('chai').expect;
var instanceLimit = require('./instanceVcpusLimit')

const oneInstance = {
    "AmiLaunchIndex": 0,
    "ImageId": "ami-00a9d4a05375b2763",
    "InstanceId": "i-0e0b690a0f60c0b90",
    "InstanceType": "m5n.large",
    "Tags": [
        {
            "Key": "Name",
            "Value": "bastion"
        }
    ],
    "VirtualizationType": "hvm",
    "CpuOptions": {
        "CoreCount": 1,
        "ThreadsPerCore": 2
    },
    "CapacityReservationSpecification": {
        "CapacityReservationPreference": "open"
    },
    "HibernationOptions": {
        "Configured": false
    },
    "Licenses": [],
    "MetadataOptions": {
        "State": "applied",
        "HttpTokens": "optional",
        "HttpPutResponseHopLimit": 1,
        "HttpEndpoint": "enabled"
    }
}

const serviceQuotas = [
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-949445B0",
        "QuotaCode": "L-949445B0",
        "QuotaName": "Running Dedicated a1 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8D142A2E",
        "QuotaCode": "L-8D142A2E",
        "QuotaName": "Running Dedicated c3 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-E4BF28E0",
        "QuotaCode": "L-E4BF28E0",
        "QuotaName": "Running Dedicated c4 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-81657574",
        "QuotaCode": "L-81657574",
        "QuotaName": "Running Dedicated c5 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-C93F66A2",
        "QuotaCode": "L-C93F66A2",
        "QuotaName": "Running Dedicated c5d Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-20F13EBD",
        "QuotaCode": "L-20F13EBD",
        "QuotaName": "Running Dedicated c5n Hosts",
        "Value": 1,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8B27377A",
        "QuotaCode": "L-8B27377A",
        "QuotaName": "Running Dedicated d2 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-5C4CD236",
        "QuotaCode": "L-5C4CD236",
        "QuotaName": "Running Dedicated f1 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-74BBB7CB",
        "QuotaCode": "L-74BBB7CB",
        "QuotaName": "Running Dedicated g2 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-DE82EABA",
        "QuotaCode": "L-DE82EABA",
        "QuotaName": "Running Dedicated g3 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-9675FDCD",
        "QuotaCode": "L-9675FDCD",
        "QuotaName": "Running Dedicated g3s Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-CAE24619",
        "QuotaCode": "L-CAE24619",
        "QuotaName": "Running Dedicated g4dn Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-84391ECC",
        "QuotaCode": "L-84391ECC",
        "QuotaName": "Running Dedicated h1 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-6222C1B6",
        "QuotaCode": "L-6222C1B6",
        "QuotaName": "Running Dedicated i2 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8E60B0B1",
        "QuotaCode": "L-8E60B0B1",
        "QuotaName": "Running Dedicated i3 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-77EE2B11",
        "QuotaCode": "L-77EE2B11",
        "QuotaName": "Running Dedicated i3en Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-3C82F907",
        "QuotaCode": "L-3C82F907",
        "QuotaName": "Running Dedicated m3 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-EF30B25E",
        "QuotaCode": "L-EF30B25E",
        "QuotaName": "Running Dedicated m4 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8B7BF662",
        "QuotaCode": "L-8B7BF662",
        "QuotaName": "Running Dedicated m5 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-B10F70D6",
        "QuotaCode": "L-B10F70D6",
        "QuotaName": "Running Dedicated m5a Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-74F41837",
        "QuotaCode": "L-74F41837",
        "QuotaName": "Running Dedicated m5ad Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8CCBD91B",
        "QuotaCode": "L-8CCBD91B",
        "QuotaName": "Running Dedicated m5d Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-DA07429F",
        "QuotaCode": "L-DA07429F",
        "QuotaName": "Running Dedicated m5dn Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-24D7D4AD",
        "QuotaCode": "L-24D7D4AD",
        "QuotaName": "Running Dedicated m5n Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-2753CF59",
        "QuotaCode": "L-2753CF59",
        "QuotaName": "Running Dedicated p2 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-A0A19F79",
        "QuotaCode": "L-A0A19F79",
        "QuotaName": "Running Dedicated p3 Hosts",
        "Value": 1,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-B601B3B6",
        "QuotaCode": "L-B601B3B6",
        "QuotaName": "Running Dedicated p3dn Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-B7208018",
        "QuotaCode": "L-B7208018",
        "QuotaName": "Running Dedicated r3 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-313524BA",
        "QuotaCode": "L-313524BA",
        "QuotaName": "Running Dedicated r4 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-EA4FD6CF",
        "QuotaCode": "L-EA4FD6CF",
        "QuotaName": "Running Dedicated r5 Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8FE30D52",
        "QuotaCode": "L-8FE30D52",
        "QuotaName": "Running Dedicated r5a Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-EC7178B6",
        "QuotaCode": "L-EC7178B6",
        "QuotaName": "Running Dedicated r5ad Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-8814B54F",
        "QuotaCode": "L-8814B54F",
        "QuotaName": "Running Dedicated r5d Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-4AB14223",
        "QuotaCode": "L-4AB14223",
        "QuotaName": "Running Dedicated r5dn Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-52EF324A",
        "QuotaCode": "L-52EF324A",
        "QuotaName": "Running Dedicated r5n Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-DE3D9563",
        "QuotaCode": "L-DE3D9563",
        "QuotaName": "Running Dedicated x1 Hosts",
        "Value": 1,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-DEF8E115",
        "QuotaCode": "L-DEF8E115",
        "QuotaName": "Running Dedicated x1e Hosts",
        "Value": 1,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-F035E935",
        "QuotaCode": "L-F035E935",
        "QuotaName": "Running Dedicated z1d Hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-74FC7D96",
        "QuotaCode": "L-74FC7D96",
        "QuotaName": "Running On-Demand F instances",
        "Value": 176,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "F/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-DB2E81BA",
        "QuotaCode": "L-DB2E81BA",
        "QuotaName": "Running On-Demand G instances",
        "Value": 768,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "G/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-1945791B",
        "QuotaCode": "L-1945791B",
        "QuotaName": "Running On-Demand Inf instances",
        "Value": 128,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "Inf/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-417A185B",
        "QuotaCode": "L-417A185B",
        "QuotaName": "Running On-Demand P instances",
        "Value": 76,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "P/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-1216C47A",
        "QuotaCode": "L-1216C47A",
        "QuotaName": "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
        "Value": 1920,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "Standard/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-7295265B",
        "QuotaCode": "L-7295265B",
        "QuotaName": "Running On-Demand X instances",
        "Value": 96,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false,
        "UsageMetric": {
            "MetricNamespace": "AWS/Usage",
            "MetricName": "ResourceCount",
            "MetricDimensions": {
                "Class": "X/OnDemand",
                "Resource": "vCPU",
                "Service": "EC2",
                "Type": "Resource"
            },
            "MetricStatisticRecommendation": "Maximum"
        }
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-5480EFD2",
        "QuotaCode": "L-5480EFD2",
        "QuotaName": "Running On-Demand inf1 hosts",
        "Value": 2,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-CEED54BB",
        "QuotaCode": "L-CEED54BB",
        "QuotaName": "Elastic IP addresses for EC2-Classic",
        "Value": 5,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-D0B7243C",
        "QuotaCode": "L-D0B7243C",
        "QuotaName": "New Reserved Instances per month",
        "Value": 20,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    },
    {
        "ServiceCode": "ec2",
        "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
        "QuotaArn": "arn:aws:servicequotas:us-east-1:978540733285:ec2/L-0263D0A3",
        "QuotaCode": "L-0263D0A3",
        "QuotaName": "Number of EIPs - VPC EIPs",
        "Value": 5,
        "Unit": "None",
        "Adjustable": true,
        "GlobalQuota": false
    }
];

const accountAttributes = [
    {
        "AttributeName": "supported-platforms",
        "AttributeValues": [
            {
                "AttributeValue": "VPC"
            }
        ]
    },
    {
        "AttributeName": "vpc-max-security-groups-per-interface",
        "AttributeValues": [
            {
                "AttributeValue": "5"
            }
        ]
    },
    {
        "AttributeName": "max-elastic-ips",
        "AttributeValues": [
            {
                "AttributeValue": "5"
            }
        ]
    },
    {
        "AttributeName": "max-instances",
        "AttributeValues": [
            {
                "AttributeValue": "20"
            }
        ]
    },
    {
        "AttributeName": "vpc-max-elastic-ips",
        "AttributeValues": [
            {
                "AttributeValue": "5"
            }
        ]
    },
    {
        "AttributeName": "default-vpc",
        "AttributeValues": [
            {
                "AttributeValue": "vpc-3baa5252"
            }
        ]
    }
];

const createCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [{
                        Instances: instances['us-east-1']
                    }],
                },
                'eu-north-1': {
                    data: [{
                        Instances: instances['eu-north-1']
                    }],
                },
            },
            describeAccountAttributes: {
                'eu-north-1': {
                    data: accountAttributes
                }
            }
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': {
                    data: serviceQuotas
                },
            }
        }
    };
};

// *****
// Account Attributes Empty, Error and Null cases
// *****
const createEmptyInstancesCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createErrorInstancesCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'bad error'
                    },
                },
            },
        },
    };
};

const createNullInstancesCache = () => {
    return {
        ec2: {
            describeInstances: null,
        },
    };
};

// *****
// Account Attributes Empty, Error and Null cases
// *****
const createEmptyAccountAttributesCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'eu-north-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['eu-north-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
            describeAccountAttributes: {
                'eu-north-1': {
                    data: [],
                },
            },
        },
    };
};

const createErrorAccountAttributesCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'eu-north-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['eu-north-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
            describeAccountAttributes: {
                'eu-north-1': {
                    err: {
                        message: 'bad error'
                    },
                },
            },
        },
    };
};

const createNullAccountAttributesCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'eu-north-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['eu-north-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
            describeAccountAttributes: null,
        },
    };
};

// *****
// vCPUs Empty, Error and Null cases
// *****
const createEmptyServiceQuotaCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['us-east-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createErrorServiceQuotaCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['us-east-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': {
                    err: {
                        message: 'bad error'
                    },
                },
            },
        },
    };
};

const createNullServiceQuotaCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['us-east-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
                'us-west-1': {
                    data: [{
                        Groups: [],
                        Instances: instances['us-east-1'],
                        OwnerId: "978540733285",
                        ReservationId: "r-045b9aa9426a550fd"
                    }],
                },
            },
        },
        servicequotas: {
            listServiceQuotas: null,
        },
    };
};

describe('instanceLimit', function () {
    describe('run', function () {
        it('should PASS if there are no instances', function (done) {
            const cache = createEmptyInstancesCache([]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if describeInstances error', function (done) {
            const cache = createErrorInstancesCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should do nothing if describeInstances is null', function (done) {
            const cache = createNullInstancesCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should return UNKOWN if cannot retrieve service quote data', function (done) {
            var instances = [];
            instances['us-east-1'] = [];

            for (i=0;i<10;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createEmptyServiceQuotaCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should return UNKOWN if listServiceQuotas data error', function (done) {
            var instances = [];
            instances['us-east-1'] = [];

            for (i=0;i<10;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createErrorServiceQuotaCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should return UNKOWN if listServiceQuotas is null', function (done) {
            var instances = [];
            instances['us-east-1'] = [];

            for (i=0;i<10;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createNullServiceQuotaCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(3);
                done();
            });
        });

        it('should return a value even if empty account attributes data (use default limit), notify user', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];

            for (i=0;i<10;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            const cache = createEmptyAccountAttributesCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should return a value even if error account attributes data (use default limit), notify user', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];

            for (i=0;i<10;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            const cache = createErrorAccountAttributesCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should return a value even if null account attributes data (use default limit), notify user', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];

            for (i=0;i<10;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            const cache = createNullAccountAttributesCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('Low Usage: should PASS if instances usage is less than the Instance Limit Percentage Fail', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<10;i++){
                instances['eu-north-1'].push(oneInstance);
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('Medium Usage: should WARN if instances usage is more than the Instance Limit Percentage Warn', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<17;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            for (i=0;i<27;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(1);
                expect(results[1].status).to.equal(1);
                done();
            });
        });

        it('Medium Usage: should FAIL for legacy region, PASS for vCPU region', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<20;i++){
                instances['eu-north-1'].push(oneInstance);
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('High Usage: should FAIL if instances usage is more than the Instance Limit Percentage Fail', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<20;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            for (i=0;i<34;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('High Usage: should FAIL for legacy region, PASS for vCPU region', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<20;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            for (i=0;i<17;i++){
                instances['us-east-1'].push(oneInstance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('High Usage: should FAIL for all vCPU regions and PASS for legacy region', function (done) {
            var instances = [];
            instances['eu-north-1'] = [];
            instances['us-east-1'] = [];

            for (i=0;i<10;i++){
                instances['eu-north-1'].push(oneInstance);
            }

            for (i=0;i<30;i++){
                instances['us-east-1'].push(oneInstance);
            }

            var instanceTemplateString = JSON.stringify(oneInstance);
            var f5Instance = JSON.parse(instanceTemplateString);
            f5Instance.InstanceType = 'f5.large';
            f5Instance.CpuOptions.CoreCount = 6;
            f5Instance.CpuOptions.ThreadsPerCore = 9;

            for (i=0;i<5;i++){
                instances['us-east-1'].push(f5Instance);
            }

            const cache = createCache(instances);

            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(3);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[2].status).to.equal(0);
                done();
            });
        });
    });
});