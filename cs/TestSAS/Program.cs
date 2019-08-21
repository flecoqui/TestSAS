using System;
using System.Net;
using System.Configuration;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace TestSAS
{
    class Program
    {
        private static string  InformationTestSAS = "TestSAS:\r\n" + "Version: {0} \r\n" + "Syntax:\r\n" +
            "TestSAS --create --account <StorageAccountName> --key <StorageAccountKey> \r\n" +
            "        --container <StorageContainer> [--blob <StorageBlob>]  \r\n" + 
            "TestSAS --help \r\n";
        static bool ParseCommandLine(string[] args,
            out string StorageAccount,
            out string StorageAccountKey,
            out string StorageContainer,
            out string StorageBlob)
        {
            string Version = "1.0.0.0";
            bool result = false;
            bool bCreate = false;
            bool bHelp = false;
            string ErrorMessage = string.Empty;
            StorageAccount = string.Empty;
            StorageAccountKey = string.Empty;
            StorageContainer = string.Empty;
            StorageBlob = string.Empty;

            if((args == null)||(args.Length == 0))
            {
                ErrorMessage = "No parameter in the command line";
            }
            else
            {
                int i = 0;
                while ((i < args.Length)&&(string.IsNullOrEmpty(ErrorMessage)))
                {
                    
                        switch(args[i++])
                        {
                            
                            case "--help":
                                bHelp = true;
                                break;
                            case "--create":
                                bCreate = true;
                                break;
                                
                            case "--account":
                                if ((i < args.Length) && (!string.IsNullOrEmpty(args[i])))
                                    StorageAccount = args[i++];
                                else
                                    ErrorMessage = "Storage Account not set";
                                break;

                            case "--key":
                                if ((i < args.Length) && (!string.IsNullOrEmpty(args[i])))
                                    StorageAccountKey = args[i++];
                                else
                                    ErrorMessage = "Storage Account Key not set";
                                break;

                            case "--container":
                                if ((i < args.Length) && (!string.IsNullOrEmpty(args[i])))
                                    StorageContainer = args[i++];
                                else
                                    ErrorMessage = "Storage Container not set";
                                break;

                            case "--blob":
                                if ((i < args.Length) && (!string.IsNullOrEmpty(args[i])))
                                    StorageBlob = args[i++];
                                else
                                    ErrorMessage = "Storage Blob not set";
                                break;

                            default:

                                if ((args[i - 1].ToLower() == "dotnet") ||
                                    (args[i - 1].ToLower() == "testsas.dll") ||
                                    (args[i - 1].ToLower() == "testsas.exe"))
                                    break;

                                ErrorMessage = "wrong parameter: " + args[i-1];
                                break;
                        }

                }
            }

            if(!string.IsNullOrEmpty(ErrorMessage))
                Console.WriteLine(ErrorMessage);

            if((bHelp)||(!string.IsNullOrEmpty(ErrorMessage)))
                Console.WriteLine(string.Format(InformationTestSAS,Version));

            if( (bCreate == true)&&
                (!string.IsNullOrEmpty(StorageAccount))&&
                (!string.IsNullOrEmpty(StorageAccountKey))&&
                (!string.IsNullOrEmpty(StorageContainer)))                
                result = true;

            return result;
        }

        public static string GetBlobSasToken(CloudBlobContainer container, string blobName, SharedAccessBlobPermissions permissions, string policyName = null)
        {
            string sasBlobToken;

            // Get a reference to a blob within the container.
            // Note that the blob may not exist yet, but a SAS can still be created for it.
            CloudBlockBlob blob = container.GetBlockBlobReference(blobName);

            if (policyName == null) {
                var adHocSas = CreateAdHocSasPolicy(permissions);

                // Generate the shared access signature on the blob, setting the constraints directly on the signature.
                sasBlobToken = blob.GetSharedAccessSignature(adHocSas);
            }
            else {
                // Generate the shared access signature on the blob. In this case, all of the constraints for the
                // shared access signature are specified on the container's stored access policy.
                sasBlobToken = blob.GetSharedAccessSignature(null, policyName);
            } 

            return sasBlobToken;
        }

 

        public static string GetContainerSasToken(CloudBlobContainer container, SharedAccessBlobPermissions permissions, string storedPolicyName = null)
        {
            string sasContainerToken;

            // If no stored policy is specified, create a new access policy and define its constraints.
            if (storedPolicyName == null) {
                var adHocSas = CreateAdHocSasPolicy(permissions);

                // Generate the shared access signature on the container, setting the constraints directly on the signature.
                sasContainerToken = container.GetSharedAccessSignature(adHocSas, null);
            }
            else {
                // Generate the shared access signature on the container. In this case, all of the constraints for the
                // shared access signature are specified on the stored access policy, which is provided by name.
                // It is also possible to specify some constraints on an ad-hoc SAS and others on the stored access policy.
                // However, a constraint must be specified on one or the other; it cannot be specified on both.
                sasContainerToken = container.GetSharedAccessSignature(null, storedPolicyName);
            }

            return sasContainerToken;
        }



        private static SharedAccessBlobPolicy CreateAdHocSasPolicy(SharedAccessBlobPermissions permissions)
        {
            // Create a new access policy and define its constraints.
            // Note that the SharedAccessBlobPolicy class is used both to define the parameters of an ad-hoc SAS, and 
            // to construct a shared access policy that is saved to the container's shared access policies. 

            return new SharedAccessBlobPolicy() {
                // Set start time to five minutes before now to avoid clock skew.
                SharedAccessStartTime = DateTime.UtcNow.AddMinutes(-5),
                SharedAccessExpiryTime = DateTime.UtcNow.AddHours(1),
                Permissions = permissions
            };
        }
        static void Main(string[] args)
        {
            string StorageAccount = string.Empty;
            string StorageAccountKey = string.Empty;
            string StorageContainer = string.Empty;
            string StorageBlob = string.Empty;


            if(ParseCommandLine(args,  out StorageAccount, out StorageAccountKey, out StorageContainer, out StorageBlob))
            {
                var permissions = SharedAccessBlobPermissions.Read |  SharedAccessBlobPermissions.List; // default to read permissions
                var storageCredentials = new StorageCredentials(StorageAccount,StorageAccountKey);
                if(storageCredentials!=null)
                {
                    var storageAccount = new CloudStorageAccount(storageCredentials,false);
                    if(StorageAccount!=null)
                    {
                        var blobClient = storageAccount.CreateCloudBlobClient();
                        if(blobClient!=null)
                        {
                            var container = blobClient.GetContainerReference(StorageContainer);
                            var sasToken =
                                !string.IsNullOrEmpty(StorageBlob) ?
                                    GetBlobSasToken(container, StorageBlob, permissions) :
                                    GetContainerSasToken(container, permissions)+ "&comp=list&restype=container";
                            if(string.IsNullOrEmpty(StorageBlob))
                                Console.WriteLine("Container SAS Url:\r\n" + container.Uri + sasToken);
                            else
                                Console.WriteLine("Blob SAS Url:\r\n" + container.Uri + "/" + StorageBlob + sasToken);
                        }
                    }
                }
            }
        }
    }
}
