# AWS Secure Static Hosting Deployment Guide

This guide walks you through deploying the **DevSecOps Portal** static website (`index.html`, `styles.css`, `app.js`) to AWS. The architecture is configured for production-grade security, adhering to the DevSecOps principles of private asset hosting, secure transport, and edge threat protection.

---

## Secure Architecture Overview

Traffic flows as follows:
`User` &rarr; `HTTPS (Port 443)` &rarr; `AWS Route 53 (DNS)` &rarr; `AWS WAF (Firewall)` &rarr; `Amazon CloudFront (CDN)` &rarr; `Origin Access Control (OAC)` &rarr; `Amazon S3 (Private Bucket)`

---

## Option 1: Manual Step-by-Step Deployment (AWS Console)

### 1. Create a Secure S3 Bucket
1. Log in to the **AWS Management Console** and navigate to **Amazon S3**.
2. Click **Create bucket**.
3. Enter a unique name (e.g., `devsecops-portal-static-xxxx`).
4. Set the region to your preference (e.g., `us-east-1`).
5. Under **Object Ownership**, select **ACLs disabled (recommended)**.
6. Under **Block Public Access settings for this bucket**:
   - Keep **"Block all public access"** checked (crucial to prevent direct internet downloads of your bucket contents).
7. Scroll to the bottom and click **Create bucket**.

### 2. Configure CloudFront (CDN) with Origin Access Control (OAC)
1. Navigate to the **CloudFront** console.
2. Click **Create distribution**.
3. In **Origin Domain**, select the S3 bucket you just created.
4. Under **Origin access**, select **Origin access control settings (recommended)**:
   - Click **Create control setting**.
   - Leave the default settings (Sign requests, Origin type: S3) and click **Create**.
5. Under **Viewer Protocol Policy**, select **Redirect HTTP to HTTPS** (ensures all traffic is TLS-encrypted).
6. Under **Web Application Firewall (WAF)**:
   - Choose **Enable security protections** to automatically set up standard AWS WAF protection rules (SQL Injection, XSS, and rate limiting protection).
7. Scroll to the bottom and set **Default root object** to `index.html`.
8. Click **Create distribution**.
9. Once created, CloudFront will display a banner: *"The S3 bucket policy needs to be updated..."*. Click **Copy policy**—you will need this for the next step.

### 3. Update S3 Bucket Policy
1. Navigate back to the **S3 console** and click on your bucket.
2. Go to the **Permissions** tab.
3. Scroll down to **Bucket policy** and click **Edit**.
4. Paste the policy you copied from the CloudFront console. It will look like this:
   ```json
   {
       "Version": "2008-10-17",
       "Statement": [
           {
               "Sid": "AllowCloudFrontServicePrincipal",
               "Effect": "Allow",
               "Principal": {
                   "ServicePrincipal": "cloudfront.amazonaws.com"
               },
               "Action": "s3:GetObject",
               "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*",
               "Condition": {
                   "StringEquals": {
                       "AWS:SourceArn": "arn:aws:cloudfront::YOUR-ACCOUNT-ID:distribution/YOUR-DISTRIBUTION-ID"
                   }
               }
           }
       ]
   }
   ```
5. Click **Save changes**. Now, only your CloudFront distribution can fetch files from your S3 bucket.

### 4. Upload the Website Files
1. In the S3 bucket, click the **Objects** tab.
2. Click **Upload**.
3. Drag and drop the following files into the upload window:
   - `index.html`
   - `styles.css`
   - `app.js`
4. Click **Upload**.
5. Once uploaded, copy the **Distribution domain name** from the CloudFront console (e.g., `d123456abcdef.cloudfront.net`) and paste it into your browser. Your secure DevSecOps website is now live!

---

## Option 2: Infrastructure as Code (Terraform)

If you have Terraform installed, you can automate this entire secure infrastructure deployment.

1. Navigate to the `terraform/` directory (if created, or use the copyable script under the "AWS Secure Hosting" tab on the website dashboard).
2. Initialize Terraform:
   ```bash
   terraform init
   ```
3. Plan the deployment to verify the resources to be created:
   ```bash
   terraform plan
   ```
4. Apply the configuration (this will prompt you to type `yes` to confirm):
   ```bash
   terraform apply
   ```
5. After execution finishes, Terraform will output your secure CloudFront URL. Upload the static files to the generated S3 bucket, and your deployment is complete!
