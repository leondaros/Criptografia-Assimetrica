/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalho2;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author jan
 */
public class Cliente {

    private static Socket socket = null;
    
    private static SecretKey chaveSessao = null;
    private static byte[] iv = null;
    
    private static Key chavePublica = null;
    private static Key chavePrivada = null;
    
    private static Key chavePubServidor = null;
    
    public static void main(String[] args) throws IOException, Exception {
        
        geraChavePubPriv();
        
        estabeleceConexao();
        
        System.out.println("");
        
        enviaMsgServidor();
        
    }
    
    private static void estabeleceConexao() throws IOException, Exception {

        socket = new Socket("127.0.0.1", 12345);
        System.out.println("Conexão estabelecida com o servidor!");
        
        //Pergunta a senha para ser derivada a chave de sessão
        System.out.println("Insira a senha que será utilizada para derivar sua chave de sessão: ");
        Scanner scanner = new Scanner(System.in);
        String sal = "881900f5d6e5cabca409675791601323";
        chaveSessao = generateDerivedKey(scanner.nextLine(), sal, 10000);
        
        //Gera iv/nonce
        iv = geraIV();
        
        //Envia chave pública para o servidor
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(chavePublica);
        System.out.println("Chave publica enviada para o servidor: ");
        System.out.println("");
        System.out.println(chavePublica.toString());
        System.out.println("");
        
        //Recebe chave pública do servidor
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        if((chavePubServidor = (Key) ois.readObject()) != null){
            System.out.println("Chave publica do servidor recebida: ");
            System.out.println("");
            System.out.println(chavePubServidor.toString());
            System.out.println("");
        }
        
        PrintStream saida = new PrintStream(socket.getOutputStream());
        Scanner entrada = new Scanner(socket.getInputStream());
        
        //Envia a mensagen 1 do protocolo
        byte[] naByte = iv;
        String na = Utils4.toHex(naByte);
        String idB = "Identificador de B";
        String chaveSessaoCifrada = cifraChaveSessao();
        String assinatura = assinaParametros(chaveSessaoCifrada + idB + na);
        saida.println(chaveSessaoCifrada + idB + na + assinatura);
        System.out.println("Mensagem 1 do protocolo enviada ao servidor: " + chaveSessaoCifrada + idB + na + assinatura);
        System.out.println("Chave de sessao Kab cifrada enviada: " + chaveSessaoCifrada);
        System.out.println("Identificador de B enviado: " + idB);
        System.out.println("Nonce A enviado: " + na);
        System.out.println("Assinatura dos parâmetros: " + assinatura);
        System.out.println("");
        
        
        //Recebe a mensagem 2 do protocolo
        String ivSessaoServidorString = null;
        if(entrada.hasNextLine()) {

            String mensagemRecebida = entrada.nextLine();
            //String chaveSessaoServidorCifrada = mensagemRecebida.substring(0, 512);
            String chaveSessaoServidorCifrada = mensagemRecebida.substring(0, 256);
            //ivSessaoServidorString = mensagemRecebida.substring(530, 562);
            ivSessaoServidorString = mensagemRecebida.substring(274, 306);
            //na = mensagemRecebida.substring(562, 594);
            na = mensagemRecebida.substring(306, 338);
            decifraChaveSessaoServidor(chaveSessaoServidorCifrada);
            //String idA = mensagemRecebida.substring(512, 530);
            String idA = mensagemRecebida.substring(256, 274);
            assinatura = mensagemRecebida.substring(338, 594);
            System.out.println("Mensagem 2 recebida: " + mensagemRecebida);
            System.out.println("Chave de sessao Kba cifrada recebida: " + chaveSessaoServidorCifrada);
            System.out.println("Identificador de A recebido: " + idA);
            System.out.println("Nonce B recebido: " + ivSessaoServidorString);
            System.out.println("Nonce A recebido: " + na);
            System.out.println("Assinatura dos parâmetros: " + assinatura);
            //Verifica assinatura
            if(verificaAssinatura(mensagemRecebida.substring(0, 338), assinatura)){
                System.out.println("Autenticidade e Integridade foram garantidas!");
            }else{
                System.out.println("Validacao da assinatura indica problemas de Autenticidade e/ou Integridade");
            }
            System.out.println("");
            //System.out.println("Recebido do servidor: " + entrada.nextLine());

        }
        
        //Envia a mensagem 3 do protocolo
        assinatura = assinaParametros(idB + ivSessaoServidorString);
        saida.println(idB + ivSessaoServidorString + assinatura);
        System.out.println("Mensagem 3 do protocolo enviada ao servidor: " + idB + ivSessaoServidorString + assinatura);
        System.out.println("Identificador de B enviado: " + idB);
        System.out.println("Nonce B enviado: " + ivSessaoServidorString);
        System.out.println("Assinatura dos parâmetros: " + assinatura);
        
    }

    private static void enviaMsgServidor() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException, IllegalStateException, InvalidCipherTextException, NoSuchProviderException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        Scanner teclado = new Scanner(System.in);

        PrintStream saida = new PrintStream(socket.getOutputStream());
        
        System.out.println("Digite a mensagem a ser enviada: ");
        
        while (teclado.hasNextLine()) {
            
            GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
            String chaveHex = Hex.encodeHexString(chaveSessao.getEncoded());
            byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
            KeyParameter chave2 = new KeyParameter(chave);
            AEADParameters params = new AEADParameters(chave2, 64, iv);
            
            gcmChave.init(true, params);
            
            
            byte[] msgBytes = teclado.nextLine().getBytes();
            int outsize = gcmChave.getOutputSize(msgBytes.length);
            byte[] msgCifradaBytes = new byte[outsize];
            
            int lengthOutc = gcmChave.processBytes(msgBytes, 0, msgBytes.length, msgCifradaBytes, 0);
        
            gcmChave.doFinal(msgCifradaBytes, lengthOutc);
            
            String msgCifradaHex = Utils4.toHex(msgCifradaBytes);
            System.out.println("Mensagem cifrada enviada:" + msgCifradaHex);
            saida.println(msgCifradaHex);
            
            System.out.println("");
            System.out.println("Digite a mensagem a ser enviada: ");
            
        }
        
    }
    
    public static SecretKey generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey sk = pbkdf2.generateSecret(spec);
            return sk;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static byte[] geraIV()throws Exception{
        byte[] iv = new byte[16];
        SecureRandom random = null;
        
        random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        
        random.nextBytes(iv);
        return iv;
    }
    
    private static void geraChavePubPriv() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        
        KeyPair pair = generator.generateKeyPair();
        chavePublica = pair.getPublic();
        chavePrivada = pair.getPrivate();
        
    }

    private static String cifraChaveSessao() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecoderException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, chavePubServidor);

        byte[] cipherText = cipher.doFinal(chaveSessao.getEncoded());
        
        String chaveSessaoCifrada = Utils4.toHex(cipherText);
        
        return chaveSessaoCifrada;
        
    }

    private static void decifraChaveSessaoServidor(String chaveSessaoServidorCifrada) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException {

        int addProvider1 = Security.addProvider(new BouncyCastleProvider());
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        
        byte[] chaveCifradaByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveSessaoServidorCifrada.toCharArray());
        byte[] chavePlanaByte = cipher.doFinal(chaveCifradaByte);
        
    }

    private static String assinaParametros(String parametros) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest hash =  MessageDigest.getInstance("SHA256");
        hash.update(Utils4.toByteArray(parametros));
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, chavePrivada);

        byte[] hashAssinadoByte = cipher.doFinal(hash.digest());
        
        String hashAssinado = Utils4.toHex(hashAssinadoByte);
        
        return hashAssinado;
        
    }

    private static boolean verificaAssinatura(String parametros, String assinatura) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest hash =  MessageDigest.getInstance("SHA256");
        hash.update(Utils4.toByteArray(parametros));
        byte[] hashParametrosCalculadoByte = hash.digest();
        String hashParametrosCalculado = Utils4.toHex(hashParametrosCalculadoByte);
        System.out.println("O hash dos parametros calculado é: " + hashParametrosCalculado);
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePubServidor);
        
        byte[] assinaturaByte = org.apache.commons.codec.binary.Hex.decodeHex(assinatura.toCharArray());
        byte[] hashRecebidoByte = cipher.doFinal(assinaturaByte);
        String hashRecebido = Utils4.toHex(hashRecebidoByte);
        System.out.println("O hash recebido foi: " + hashRecebido);
        
        return hashParametrosCalculado.equals(hashRecebido);
        
    }
    
}
