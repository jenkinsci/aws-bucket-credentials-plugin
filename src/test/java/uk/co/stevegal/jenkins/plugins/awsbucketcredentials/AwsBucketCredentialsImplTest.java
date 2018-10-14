package uk.co.stevegal.jenkins.plugins.awsbucketcredentials;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.Secret;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.Whitebox;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyByte;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.*;


/**
 * Created by stevegal on 05/02/2017.
 */
public class AwsBucketCredentialsImplTest {

    private AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
            "EU_WEST_1", "bucketUri", "/bucketPath", "username", true,
            "mydescription", true, true,"someEncryptContextKey", "kmsEncryptContextValue", "host", "9000");

    private AwsS3ClientBuilder mockClientBuilder;
    private AwsKmsClientBuilder mockKmsClientBuilder;

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Before
    public void setupMocks() {
        this.mockClientBuilder = mock(AwsS3ClientBuilder.class);
        this.mockKmsClientBuilder = mock(AwsKmsClientBuilder.class);
        Whitebox.setInternalState(test, "amazonS3ClientBuilder", mockClientBuilder);
        Whitebox.setInternalState(test, "amazonKmsClientBuilder", mockKmsClientBuilder);

    }

    @Test
    public void calculatesMeaningfulDisplayName() {
        String displayName = test.getDisplayName();
        assertThat(displayName).isEqualTo("bucketUri:/bucketPath");
    }

    @Test
    public void descriptorHasADisplayName() {
        AwsBucketCredentialsImpl.DescriptorImpl descriptorTest = new AwsBucketCredentialsImpl.DescriptorImpl();
        String displayName = descriptorTest.getDisplayName();
        assertThat(displayName).isEqualTo("AWS Bucket Credentials");
    }

    @Test
    public void username() {
        String username = test.getUsername();
        assertThat(username).isEqualTo("username");
    }

    @Test
    public void passwordUsesTheS3Bucket() throws Exception {
        S3Object mockS3Object = mock(S3Object.class);
        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        when(mockClientBuilder.build()).thenReturn(mockClient);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        AWSKMSClient mockKmsClient = mock(AWSKMSClient.class);
        when(mockKmsClientBuilder.build()).thenReturn(mockKmsClient);

        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
                .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
                .thenReturn(-1);

        DecryptResult result = new DecryptResult();
        CharsetEncoder charsetEncoder = Charset.forName("UTF-8").newEncoder();
        result.setPlaintext(charsetEncoder.encode(CharBuffer.wrap("password")));
        when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(result);

        Secret secret = test.getPassword();

        // have we got the expected password
        assertThat(secret.getPlainText()).isEqualTo("password");

        // have we used the bucket
        ArgumentCaptor<GetObjectRequest> capturedObjectRequest = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(mockClient).getObject(capturedObjectRequest.capture());
        assertThat(capturedObjectRequest.getValue().getBucketName()).isEqualTo("bucketUri");
        assertThat(capturedObjectRequest.getValue().getS3ObjectId().getKey()).isEqualTo("/bucketPath");

        // have we used kms to decrypt
        ArgumentCaptor<DecryptRequest> capturedDecryptRequest = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(mockKmsClient).decrypt(capturedDecryptRequest.capture());
        assertThat(capturedDecryptRequest.getValue().getEncryptionContext()).containsEntry("someEncryptContextKey", "kmsEncryptContextValue");
        ByteBuffer ciphertextBlob = capturedDecryptRequest.getValue().getCiphertextBlob();
        assertThat(new String(Charset.forName("UTF-8").decode(ciphertextBlob).array())).isEqualTo("encryptedPassword");

    }

    @Test
    public void regionSetInKmsAndS3Clients() throws Exception {
        AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
                "eu-west-1", "bucketUri", "/bucketPath", "username", true,
                "mydescription",true,true,null,null, "host", "8080");
        AwsS3ClientBuilder clientBuilder = (AwsS3ClientBuilder) Whitebox.getInternalState(test, "amazonS3ClientBuilder");
        AmazonS3Client amazonS3Client = clientBuilder.build();
        assertThat(amazonS3Client.getRegion().toString()).isEqualTo(Region.getRegion(Regions.EU_WEST_1).toString());
        {
            ClientConfiguration configuration = (ClientConfiguration) Whitebox.getInternalState(amazonS3Client, "clientConfiguration");
            assertThat(configuration.getProxyHost()).isEqualTo("host");
            assertThat(configuration.getProxyPort()).isEqualTo(8080);
        }
        AwsKmsClientBuilder awskmsClient = (AwsKmsClientBuilder) Whitebox.getInternalState(test, "amazonKmsClientBuilder");
        String region = (String) Whitebox.getInternalState(awskmsClient, "region");
        assertThat(region).contains("eu-west-1");
        {
            String configuration = (String) Whitebox.getInternalState(awskmsClient, "host");
            assertThat(configuration).isEqualTo("host");
            int port = (Integer) Whitebox.getInternalState(awskmsClient, "port");
            assertThat(port).isEqualTo(8080);
        }
    }

    @Test
    public void turnOffProxyIgnoresSettings() throws Exception {
        AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
                "eu-west-1", "bucketUri", "/bucketPath", "username", false,
                "mydescription",true,false,null, null, "host", "8080");
        AwsS3ClientBuilder clientBuilder = (AwsS3ClientBuilder) Whitebox.getInternalState(test, "amazonS3ClientBuilder");
        AmazonS3Client amazonS3Client = clientBuilder.build();
        assertThat(amazonS3Client.getRegion().toString()).isEqualTo(Region.getRegion(Regions.EU_WEST_1).toString());
        {
            ClientConfiguration configuration = (ClientConfiguration) Whitebox.getInternalState(amazonS3Client, "clientConfiguration");
            assertThat(configuration.getProxyHost()).isNull();
        }
        AwsKmsClientBuilder awskmsClient = (AwsKmsClientBuilder) Whitebox.getInternalState(test, "amazonKmsClientBuilder");
        String region = (String) Whitebox.getInternalState(awskmsClient, "region");
        assertThat(region).contains("eu-west-1");
        {
            String configuration = (String) Whitebox.getInternalState(awskmsClient, "host");
            assertThat(configuration).isNull();
        }
    }

    @Test
    public void doesNotUseEncryptContextIfNotProvided() throws Exception {
        AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
                "EU_WEST_1", "bucketUri", "/bucketPath", "username", true,
                "mydescription", true,true,null, null, "host", "9000");
        Whitebox.setInternalState(test, "amazonS3ClientBuilder", mockClientBuilder);
        Whitebox.setInternalState(test, "amazonKmsClientBuilder", mockKmsClientBuilder);

        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        when(mockClientBuilder.build()).thenReturn(mockClient);

        AWSKMSClient mockKmsClient = mock(AWSKMSClient.class);
        when(mockKmsClientBuilder.build()).thenReturn(mockKmsClient);
        S3Object mockS3Object = mock(S3Object.class);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
                .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
                .thenReturn(-1);

        DecryptResult result = new DecryptResult();
        CharsetEncoder charsetEncoder = Charset.forName("UTF-8").newEncoder();
        result.setPlaintext(charsetEncoder.encode(CharBuffer.wrap("password")));
        when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(result);

        Secret secret = test.getPassword();

        // have we got the expected password
        assertThat(secret.getPlainText()).isEqualTo("password");

        // have we used the bucket
        ArgumentCaptor<GetObjectRequest> capturedObjectRequest = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(mockClient).getObject(capturedObjectRequest.capture());
        assertThat(capturedObjectRequest.getValue().getBucketName()).isEqualTo("bucketUri");
        assertThat(capturedObjectRequest.getValue().getS3ObjectId().getKey()).isEqualTo("/bucketPath");

        // have we used kms to decrypt
        ArgumentCaptor<DecryptRequest> capturedDecryptRequest = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(mockKmsClient).decrypt(capturedDecryptRequest.capture());
        assertThat(capturedDecryptRequest.getValue().getEncryptionContext()).isEmpty();
        ByteBuffer ciphertextBlob = capturedDecryptRequest.getValue().getCiphertextBlob();
        assertThat(new String(Charset.forName("UTF-8").decode(ciphertextBlob).array())).isEqualTo("encryptedPassword");

        verify(mockS3Object).close();

    }

    @Test
    public void doesNotUseEncryptContextIfEmptyProvided() throws Exception {
        AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
            "EU_WEST_1", "bucketUri", "/bucketPath", "username", true,
            "mydescription", true, true,"", "", "host", "9000");
        Whitebox.setInternalState(test, "amazonS3ClientBuilder", mockClientBuilder);
        Whitebox.setInternalState(test, "amazonKmsClientBuilder", mockKmsClientBuilder);

        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        when(mockClientBuilder.build()).thenReturn(mockClient);

        AWSKMSClient mockKmsClient = mock(AWSKMSClient.class);
        when(mockKmsClientBuilder.build()).thenReturn(mockKmsClient);
        S3Object mockS3Object = mock(S3Object.class);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
            .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
            .thenReturn(-1);

        DecryptResult result = new DecryptResult();
        CharsetEncoder charsetEncoder = Charset.forName("UTF-8").newEncoder();
        result.setPlaintext(charsetEncoder.encode(CharBuffer.wrap("password")));
        when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(result);

        Secret secret = test.getPassword();

        // have we got the expected password
        assertThat(secret.getPlainText()).isEqualTo("password");

        // have we used the bucket
        ArgumentCaptor<GetObjectRequest> capturedObjectRequest = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(mockClient).getObject(capturedObjectRequest.capture());
        assertThat(capturedObjectRequest.getValue().getBucketName()).isEqualTo("bucketUri");
        assertThat(capturedObjectRequest.getValue().getS3ObjectId().getKey()).isEqualTo("/bucketPath");

        // have we used kms to decrypt
        ArgumentCaptor<DecryptRequest> capturedDecryptRequest = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(mockKmsClient).decrypt(capturedDecryptRequest.capture());
        assertThat(capturedDecryptRequest.getValue().getEncryptionContext()).isEmpty();
        ByteBuffer ciphertextBlob = capturedDecryptRequest.getValue().getCiphertextBlob();
        assertThat(new String(Charset.forName("UTF-8").decode(ciphertextBlob).array())).isEqualTo("encryptedPassword");

        verify(mockS3Object).close();

    }

    @Test
    public void closesIfIOExceptionWhileReading() throws Exception {
        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        when(mockClientBuilder.build()).thenReturn(mockClient);

        AWSKMSClient mockKmsClient = mock(AWSKMSClient.class);
        when(mockKmsClientBuilder.build()).thenReturn(mockKmsClient);

        S3Object mockS3Object = mock(S3Object.class);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
                .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
                .thenThrow(new IOException("something went wrong"))
                .thenReturn(-1);

        DecryptResult result = new DecryptResult();
        CharsetEncoder charsetEncoder = Charset.forName("UTF-8").newEncoder();
        result.setPlaintext(charsetEncoder.encode(CharBuffer.wrap("password")));
        when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(result);

        Secret secret = null;
        try {
            secret = test.getPassword();
            TestCase.fail("should have thrown exception");
        } catch (AwsBucketReadingException e) {
            assertThat(e.getCause()).isInstanceOf(IOException.class);
        }

        // have we used the bucket
        ArgumentCaptor<GetObjectRequest> capturedObjectRequest = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(mockClient).getObject(capturedObjectRequest.capture());
        assertThat(capturedObjectRequest.getValue().getBucketName()).isEqualTo("bucketUri");
        assertThat(capturedObjectRequest.getValue().getS3ObjectId().getKey()).isEqualTo("/bucketPath");

        // and we have closed it even if there was an exception
        verify(mockS3Object).close();
    }

    @Test
    public void canRetrieveDataViaGetters() {
        String bucketName = this.test.getBucketName();
        String bucketPath = this.test.getBucketPath();
        final String kmsEncryptionContextKey = this.test.getKmsEncryptionContextKey();
        final String kmsSecretName = this.test.getKmsEncryptionContextValue();
        final boolean isKms = this.test.isKmsProxy();
        final boolean isS3 = this.test.isS3Proxy();
        final String host = this.test.getProxyHost();
        final String port = this.test.getProxyPort();

        assertThat(bucketName).isEqualTo("bucketUri");
        assertThat(bucketPath).isEqualTo("/bucketPath");
        assertThat(kmsEncryptionContextKey).isEqualTo("someEncryptContextKey");
        assertThat(kmsSecretName).isEqualTo("kmsEncryptContextValue");
        assertThat(isKms).isTrue();
        assertThat(isS3).isTrue();
        assertThat(host).isEqualTo("host");
        assertThat(port).isEqualTo("9000");
        assertThat(this.test.isUseKms()).isTrue();
        assertThat(this.test.getKmsEncryptionContextKey()).isEqualTo("someEncryptContextKey");
        assertThat(this.test.getKmsEncryptionContextValue()).isEqualTo("kmsEncryptContextValue");

    }

    @Test
    public void afterDeserialiseCanStillDecrypt() throws Exception {
        byte[] objectBytes = this.serialise(this.test);
        AwsBucketCredentialsImpl newObj = this.deserialise(objectBytes,AwsBucketCredentialsImpl.class);

        S3Object mockS3Object = mock(S3Object.class);
        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        AwsS3ClientBuilder mockClientBuilder = (AwsS3ClientBuilder)Whitebox.getInternalState(newObj,"amazonS3ClientBuilder");
        when(mockClientBuilder.build()).thenReturn(mockClient);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        AWSKMSClient mockKmsClient = mock(AWSKMSClient.class);
        AwsKmsClientBuilder mockKmsClientBuilder =  (AwsKmsClientBuilder)Whitebox.getInternalState(newObj,"amazonKmsClientBuilder");
        when(mockKmsClientBuilder.build()).thenReturn(mockKmsClient);

        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
                .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
                .thenReturn(-1);

        DecryptResult result = new DecryptResult();
        CharsetEncoder charsetEncoder = Charset.forName("UTF-8").newEncoder();
        result.setPlaintext(charsetEncoder.encode(CharBuffer.wrap("password")));
        when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(result);

        Secret secret = newObj.getPassword();

        // if we get here we have passed.
        assertThat(secret.getPlainText()).isEqualTo("password");

    }

    @Test
    public void whenNoKmsSpecifiedJustUsesGetFromBucket() throws Exception {
        AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
                "EU_WEST_1", "bucketUri", "/bucketPath", "username", true,
                "mydescription", false,false,null,null, "host", "9000");
        Whitebox.setInternalState(test, "amazonS3ClientBuilder", mockClientBuilder);
        Whitebox.setInternalState(test, "amazonKmsClientBuilder", mockKmsClientBuilder);

        AmazonS3Client mockClient = mock(AmazonS3Client.class);
        when(mockClientBuilder.build()).thenReturn(mockClient);


        S3Object mockS3Object = mock(S3Object.class);
        when(mockClient.getObject(any(GetObjectRequest.class))).thenReturn(mockS3Object);
        S3ObjectInputStream mockS3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);
        when(mockS3ObjectInputStream.read(new byte[anyInt()], anyInt(), anyByte()))
                .thenAnswer(new WriteBufferAnswer("encryptedPassword".getBytes()))
                .thenReturn(-1);

        Secret secret = test.getPassword();

        // have we got the expected password
        assertThat(secret.getPlainText()).isEqualTo("encryptedPassword");

        // have we used the bucket
        ArgumentCaptor<GetObjectRequest> capturedObjectRequest = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(mockClient).getObject(capturedObjectRequest.capture());
        assertThat(capturedObjectRequest.getValue().getBucketName()).isEqualTo("bucketUri");
        assertThat(capturedObjectRequest.getValue().getS3ObjectId().getKey()).isEqualTo("/bucketPath");

        // have we not used kms to decrypt
        verifyNoMoreInteractions(mockKmsClientBuilder);

        verify(mockS3Object).close();
    }

    @Test
    public void proxyIsSetButNullValuesShouldNotUseProxy() {
      AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
          "eu-west-1", "bucketUri", "/bucketPath", "username", true,
          "mydescription", true,true,null,null, null, null);
      AwsS3ClientBuilder clientBuilder = (AwsS3ClientBuilder) Whitebox.getInternalState(test, "amazonS3ClientBuilder");
      AmazonS3Client amazonS3Client = clientBuilder.build();
      {
        ClientConfiguration configuration = (ClientConfiguration) Whitebox.getInternalState(amazonS3Client, "clientConfiguration");
        assertThat(configuration.getProxyHost()).isNull();
      }
      AwsKmsClientBuilder awskmsClient = (AwsKmsClientBuilder) Whitebox.getInternalState(test, "amazonKmsClientBuilder");
      {
        String configuration = (String) Whitebox.getInternalState(awskmsClient, "host");
        assertThat(configuration).isNull();
      }
    }

  @Test
  public void proxyIsSetButEmptyValuesShouldNotUseProxy() {
    AwsBucketCredentialsImpl test = new AwsBucketCredentialsImpl(CredentialsScope.GLOBAL, "myId",
        "eu-west-1", "bucketUri", "/bucketPath", "username", true,
        "mydescription", true,true,null,null, "", "");
    AwsS3ClientBuilder clientBuilder = (AwsS3ClientBuilder) Whitebox.getInternalState(test, "amazonS3ClientBuilder");
    AmazonS3Client amazonS3Client = clientBuilder.build();
    {
      ClientConfiguration configuration = (ClientConfiguration) Whitebox.getInternalState(amazonS3Client, "clientConfiguration");
      assertThat(configuration.getProxyHost()).isNull();
    }
    AwsKmsClientBuilder awskmsClient = (AwsKmsClientBuilder) Whitebox.getInternalState(test, "amazonKmsClientBuilder");
    {
      String configuration = (String) Whitebox.getInternalState(awskmsClient, "host");
      assertThat(configuration).isNull();
    }
  }

    private byte[] serialise(Serializable object) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        try {
            oos.writeObject(object);
            return baos.toByteArray();
        } finally {
            try {
                oos.close();
            } catch (IOException exception) {
                // no impl
            }
            try {
                baos.close();
            } catch (IOException exception) {
                // no impl
            }
        }

    }

    private <T> T deserialise(byte[] objectBytes, Class<T> clazz) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(objectBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        try {
            return (T)ois.readObject();
        } finally {
            try {
                ois.close();
            } catch (IOException exception ) {
                // no impl
            }

            try {
                bais.close();
            } catch (IOException exception) {
                // no impl
            }
        }
    }

    private static class WriteBufferAnswer implements Answer<Integer> {

        private byte[] bytes;

        public WriteBufferAnswer(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public Integer answer(InvocationOnMock invocation) throws Throwable {
            byte[] buffer = (byte[]) invocation.getArguments()[0];
            System.arraycopy(bytes, 0, buffer, 0, bytes.length);
            return bytes.length;
        }
    }

}