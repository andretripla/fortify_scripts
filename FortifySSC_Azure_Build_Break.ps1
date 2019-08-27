################################################
# Variables Definition
################################################
$sscUser = args[0]
$sscPass = args[1]
$appVersion = args[2]
$criticalLimit = args[3] -as [int]
$highLimit = args[4] -as [int]

#$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $sscUser,$sscPass)))
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $sscUser,$sscPass)))
$tokenHeaders = @{ 'Authorization' = ("Basic {0}" -f $base64AuthInfo) }

$requestToken = 'https://sast.ailos.coop.br/ssc/api/v1/tokens'
$requestIssues = "https://sast.ailos.coop.br/ssc/api/v1/projectVersions/$appVersion/issueSummaries?seriestype=ISSUE_FRIORITY&groupaxistype=ISSUE_FRIORITY&showhidden=true&showremoved=true&showsuppressed=true"

$tokenBody = "{ ""type"": ""UnifiedLoginToken"" }"

################################################
# Adding certificate exception to prevent API errors
################################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

################################################
# Building API string & invoking REST API
################################################

$response = Invoke-RestMethod -Uri $requestToken -Method POST -Headers $tokenHeaders -ContentType 'application/json' -Body $tokenBody

$issueHeaders = @{ 'Authorization' = "FortifyToken {0}" -f $response.data.token }

$responseIssues = Invoke-RestMethod -Uri $requestIssues -Method GET -ContentType 'application/json' -Headers $issueHeaders 

################################################
# Issues verification for build break
################################################

foreach ($i in $responseIssues.data.series) 
{
    if ( $i.seriesName.Equals("Critical") )
    {
        if ($i.points.y -ge $criticalLimit)
        {
            # Break pipeline
            exit 1
        }
        # Continue on pipeline
        exit 0
    } 
    elseif ( $i.seriesName.Equals("High") )
    {
        if ($i.points.y -ge $highLimit)
        {
            # Break pipeline
            exit 1
        }
        # Continue on pipeline
        exit 0
    } 
    else
    {
        # Continue on pipeline
        exit 0
    }
}
