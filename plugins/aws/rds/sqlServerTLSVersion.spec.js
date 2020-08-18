var assert = require('assert');
var expect = require('chai').expect;
var sqlServerTLSVersion = require('./sqlServerTLSVersion.js');

const parameterGroups = [
    {
        "DBParameterGroupName": "default.sqlserver-ex-14.0",
        "DBParameterGroupFamily": "sqlserver-ex-14.0",
        "Description": "Default parameter group for sqlserver-ex-14.0",
        "DBParameterGroupArn": "arn:aws:rds:us-east-1:560213429563:pg:default.sqlserver-ex-14.0"
    },
    {
        "DBParameterGroupName": "ex-g",
        "DBParameterGroupFamily": "sqlserver-ex-14.0",
        "Description": "abv",
        "DBParameterGroupArn": "arn:aws:rds:us-east-1:560213429563:pg:ex-g"
    }
];

const groupParameters = [
    [
        {
            ParameterName: '692',
            ParameterValue: '0',
            Description: 'Disables fast inserts for bulk load operations of storing data in a heap or clustered index. If batch size cannot be increased this SQL Server trace flag will reduce reserved unused space at the cost of performance.',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: '7806',
            ParameterValue: '1',
            Description: 'Enables a dedicated administrator connection (DAC) on SQL Server Express.',
            Source: 'system',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'access check cache bucket count',
            ParameterValue: '0',
            Description: 'Number of has buckets used by the internal access check result cache',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-16384',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'access check cache quota',
            ParameterValue: '0',
            Description: 'Number of entries used by the internal access check result cache',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ad hoc distributed queries',
            ParameterValue: '0',
            Description: 'Enable ad hoc distributed queries using OPENROWSET and OPENDATASOURCE',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'affinity i/o mask',
            ParameterValue: '0',
            Description: 'Bind disk I/O to specified subset of CPUs',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '-2147483648-2147483647',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'affinity mask',
            ParameterValue: '0',
            Description: 'Dynamically control CPU affinity',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '-2147483648-2147483647',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'agent xps',
            ParameterValue: '1',
            Description: 'Enable the SQL Server Agent extended stored procedures on this serve',
            Source: 'system',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'allow polybase export',
            ParameterValue: '0',
            Description: 'Allow INSERT into a Hadoop external table',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'allow updates',
            ParameterValue: '0',
            Description: 'Setting has no effect',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'automatic soft-numa disabled',
            ParameterValue: '0',
            Description: 'Automatic soft-NUMA is enabled by default',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'c2 audit mode',
            ParameterValue: '0',
            Description: 'Enable C2 auditing',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'clr enabled',
            ParameterValue: '0',
            Description: 'Whether assemblies can be run by SQL Server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'clr strict security',
            ParameterValue: '1',
            Description: 'clr strict security',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'contained database authentication',
            ParameterValue: '0',
            Description: 'Enable contained databases authentication to create or attach contained databases to Database Engine without authenticating a login at the Database Engine level',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'cost threshold for parallelism',
            ParameterValue: '5',
            Description: 'Threshold at which Microsoft SQL Server creates and runs parallel plans for queries',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'cross db ownership chaining',
            ParameterValue: '0',
            Description: 'Configure cross-database ownership chaining for an instance of Microsoft SQL Server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'cursor threshold',
            ParameterValue: '-1',
            Description: 'Number of rows in the cursor set at which cursor keysets are generated asynchronously',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '-1-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'database mail xps',
            ParameterValue: '0',
            Description: 'Enable Database Mail on the server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'default full-text language',
            ParameterValue: '1033',
            Description: 'Default language value for full-text indexed columns',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'default language',
            ParameterValue: '0',
            Description: 'Default language for all newly created logins',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-33',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'default trace enabled',
            ParameterValue: '1',
            Description: 'Enable or disable the default trace log files',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'disallow results from triggers',
            ParameterValue: '0',
            Description: 'Whether triggers can return result sets',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'external scripts enabled',
            ParameterValue: '0',
            Description: 'Allows execution of external scripts',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'filestream access level',
            ParameterValue: '0',
            Description: 'Change the FILESTREAM access level for this instance of SQL Server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'fill factor (%)',
            ParameterValue: '0',
            Description: 'Server-wide default fill-factor value',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '0-100',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ft crawl bandwidth (max)',
            ParameterValue: '100',
            Description: 'Maximum size to which the ppool of large memory buffers can grow for full-text searching',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ft crawl bandwidth (min)',
            ParameterValue: '0',
            Description: 'Minimum size to which the ppool of large memory buffers can grow for full-text searching',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ft notify bandwidth (max)',
            ParameterValue: '100',
            Description: 'Maximum size to which the pool of small memory buffers can grow for full-text searching',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ft notify bandwidth (min)',
            ParameterValue: '0',
            Description: 'Minimum size to which the pool of small memory buffers can grow for full-text searching',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'index create memory (kb)',
            ParameterValue: '0',
            Description: 'Maximum amount of memory initially allocated for creating indexes',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0,704-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'in-doubt xact resolution',
            ParameterValue: '0',
            Description: 'Control default outcome of transactions that the Microsoft Distributed Transaction Coordinator (MS DTC) is unable to resolve',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'lightweight pooling',
            ParameterValue: '0',
            Description: 'Whether to switch to fiber mode scheduling',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'locks',
            ParameterValue: '0',
            Description: 'Maximum number of available locks',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '0,5000-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'max degree of parallelism',
            ParameterValue: '0',
            Description: 'Number of processors to use in a parallel plan execution',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-64',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'max full-text crawl range',
            ParameterValue: '4',
            Description: 'Number of partitions that Microsoft SQL Server should use during a full index crawl',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-256',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'max server memory (mb)',
            ParameterValue: '{DBInstanceClassMemory/1048576}',
            Description: 'Maximum amount of memory in megabytes in the buffer pool used by an instance of Microsoft SQL Server',
            Source: 'system',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '16-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'max text repl size (b)',
            ParameterValue: '65536',
            Description: 'Maximum size in bytes of text, ntext, varchar(max), nvarchar(max), varbinary(max), xml, and image data that can be added to a replicated column or captured in a single INSERT, UPDATE, WRITETEXT, or UPDATETEXT statement',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '-1-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'max worker threads',
            ParameterValue: '0',
            Description: 'Number of worker threads available to Microsoft SQL Server processes',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '0,128-32767',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'media retention',
            ParameterValue: '0',
            Description: 'System-wide default length of time to retain each backup set',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-365',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'min memory per query (kb)',
            ParameterValue: '1024',
            Description: 'Minimum amount of memory in kilobytes that are allocated for the execution of a query',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '512-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'min server memory (mb)',
            ParameterValue: '0',
            Description: 'Minimum amount of memory in megabytes in the buffer pool used by an instance of Microsoft SQL Server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'nested triggers',
            ParameterValue: '1',
            Description: 'Control whether an AFTER trigger can cascade',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'network packet size (b)',
            ParameterValue: '4096',
            Description: 'Packet size (in bytes) used across the entire network',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '512-32767',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ole automation procedures',
            ParameterValue: '0',
            Description: 'Whether OLE Automation objects can be instantiated within Transact-SQL batches',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'open objects',
            ParameterValue: '0',
            Description: 'Setting has no effect',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'optimize for ad hoc workloads',
            ParameterValue: '0',
            Description: 'Improve efficiency of the plan cache for workloads that contain many single use ad hoc batches',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'ph timeout (s)',
            ParameterValue: '60',
            Description: 'Time, in seconds, that the full-text protocol handler should wait to connect to a database before timing-out',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '1-3600',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'polybase network encryption',
            ParameterValue: '0',
            Description: 'Configure SQL Server to encrypt control and data channels when using PolyBase',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'priority boost',
            ParameterValue: '0',
            Description: 'Whether Microsoft SQL Server should run at a higher Windows Server scheduling priority than other processes on the same computer',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'query governor cost limit',
            ParameterValue: '0',
            Description: 'Upper limit on the time period in which query can run',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'query wait (s)',
            ParameterValue: '-1',
            Description: 'Time in seconds that a query waits for resources before timing out',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '-1-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.3des168',
            ParameterValue: 'default',
            Description: 'Triple DES encryption cipher with a 168-bit key length',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.curve25519',
            ParameterValue: 'default',
            Description: 'Curve25519 elliptic-curve encryption. Not supported for all engine versions. ',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.3049.1.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.diffie-hellman',
            ParameterValue: 'default',
            Description: 'Diffie-Hellman key-exchange encryption',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.diffie-hellman-min-key-bit-length',
            ParameterValue: 'default',
            Description: 'Minimum bit length for Diffie-Hellman keys',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, 1024, 2048, 4096',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.fips',
            ParameterValue: '0',
            Description: 'FIPS enforcement.',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.force_ssl',
            ParameterValue: '0',
            Description: 'Force SSL connections.',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.rc4',
            ParameterValue: 'default',
            Description: 'RC4 stream cipher',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls10',
            ParameterValue: 'disabled',
            Description: 'TLS 1.0.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls11',
            ParameterValue: 'disabled',
            Description: 'TLS 1.1.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls12',
            ParameterValue: 'default',
            Description: 'TLS 1.2.',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: false,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'recovery interval (min)',
            ParameterValue: '0',
            Description: 'Maximum number of minutes per database that Microsoft SQL Server needs to recover databases',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote access',
            ParameterValue: '1',
            Description: 'Control the execution of stored procedure from local or remote servers on which instances of Microsoft SQL Server are running',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote admin connections',
            ParameterValue: '0',
            Description: 'Enable client applications on remote computers to use the dedicated administrator connection (DAC)',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote data archive',
            ParameterValue: '0',
            Description: 'Allow the use of the REMOTE_DATA_ARCHIVE data access for databases',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote login timeout (s)',
            ParameterValue: '20',
            Description: 'Number of seconds to wait before returning from a failed attempt to log in to a remote server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote proc trans',
            ParameterValue: '0',
            Description: 'Protect the actions of a server-to-server procedure through a Microsoft Distributed Transaction Coordinator (MS DTC) transaction',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'remote query timeout (s)',
            ParameterValue: '600',
            Description: 'How long, in seconds, a remote operation can take before Microsoft SQL Server times out',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-2147483647',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'replication xps',
            ParameterValue: '0',
            Description: 'Internal use only',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'scan for startup procs',
            ParameterValue: '1',
            Description: 'Scan for automatic execution of stored procedures at Microsoft SQL Server startup time',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'server trigger recursion',
            ParameterValue: '1',
            Description: 'Whether to allow server-level triggers to fire recursively',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'set working set size',
            ParameterValue: '0',
            Description: 'Setting has no effect',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'show advanced options',
            ParameterValue: '1',
            Description: 'Display the sp_configure system stored procedure advanced options',
            Source: 'system',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'smo and dmo xps',
            ParameterValue: '1',
            Description: 'Enable SQL Server Management Object (SMO) and SQL Distributed Management Object (SQL-DMO) extended stored procedures on this server',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'transform noise words',
            ParameterValue: '0',
            Description: 'Suppress an error message if noise words cause a Boolean operation on a full-text query to return zero rows',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'two digit year cutoff',
            ParameterValue: '2049',
            Description: 'Cutoff year for interpreting two-digit years as four-digit years',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '1753-9999',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'user connections',
            ParameterValue: '0',
            Description: 'Maximum number of simultaneous user connections. Please note that the service may use up to 40 connections for system maintenance.',
            Source: 'engine-default',
            ApplyType: 'static',
            DataType: 'integer',
            AllowedValues: '0,40-32767',
            IsModifiable: true,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'user options',
            ParameterValue: '0',
            Description: 'Specify global default query processing options for all users',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'integer',
            AllowedValues: '0-32767',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'xp_cmdshell',
            ParameterValue: '0',
            Description: 'Enable whether the xp_cmdshell extended stored procedure can be executed on the system',
            Source: 'engine-default',
            ApplyType: 'dynamic',
            DataType: 'boolean',
            AllowedValues: '0,1',
            IsModifiable: false,
            MinimumEngineVersion: '14.00.1000.169.v1',
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        }
    ]
];

const createCache = (parameterGroups, groupParameters) => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': {
                    data: parameterGroups
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    'ex-g': {
                            data: {
                                Parameters: groupParameters
                            }
                    }
                },
            },
        },
    };
};


const createErrorCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing parameter groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('sqlServerTLSVersion', function () {
    describe('run', function () {

        it('should PASS if unable to get parameter groups', function (done) {
            const cache = createCache([]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to get parameter groups', function (done) {
            const cache = createNullCache();
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        // it('should UNKNOWN if error occurs while fetching server certificates metadata list', function (done) {
        //     const cache = createErrorCache();
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(3);
        //         done();
        //     });
        // });

        // it('should FAIL if server certificate data is empty', function (done) {
        //     const cache = createCache([listCertificates[0]], []);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(3);
        //         done();
        //     });
        // });

        // it('should FAIL if server certificate body empty', function (done) {
        //     const cache = createCertificateCache([listCertificates[0]], certificates[2]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(3);
        //         done();
        //     });
        // });

        it('should PASS if parameter group uses TLS version 1.2', function (done) {
            const cache = createCache([parameterGroups[1]], groupParameters[0]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        // it('should WARN if server certificate has less than 2048 bit key length', function (done) {
        //     const cache = createCertificateCache([listCertificates[0]], certificates[1]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(1);
        //         done();
        //     });
        // });
    });
});