/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalho2;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
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

        /*Socket cliente = new Socket("127.0.0.1", 12345);

        System.out.println("O cliente se conectou ao servidor!");

        Scanner teclado = new Scanner(System.in);

        PrintStream saida = new PrintStream(cliente.getOutputStream());

        while (teclado.hasNextLine()) {

            saida.println(teclado.nextLine());

        }

        saida.close();

        teclado.close();*/
        
        geraChavePubPriv();
        
        estabeleceConexao();
        
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
        
        //Transforma chave pública em string
        String chavePubString = chavePublica.toString();
        
        //Envia chave pública para o servidor
        /*
        PrintStream saida = new PrintStream(socket.getOutputStream());
        saida.println(chavePubString);
        System.out.println("Chave publica enviada para o servidor: " + chavePubString);
        */
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
        
        /*StringBuilder sb = new StringBuilder();
      
        //Recebe chave pública do servidor
        Scanner entrada = new Scanner(socket.getInputStream());
        if(entrada.hasNextLine()) {
            
            //Necessita de três linhas para a chave pública
            sb.append(entrada.nextLine());
            
            if(entrada.hasNextLine()){
                
                sb.append(System.lineSeparator());
                sb.append(entrada.nextLine());
                
                if(entrada.hasNextLine()){
                    sb.append(System.lineSeparator());
                    sb.append(entrada.nextLine());
                }
                
            }
            System.out.println("Chave publica do servidor recebida: " + sb.toString());

        }*/
        
        PrintStream saida = new PrintStream(socket.getOutputStream());
        Scanner entrada = new Scanner(socket.getInputStream());
        
        //Envia a mensagen 1 do protocolo
        byte[] naByte = iv;
        String na = Utils4.toHex(naByte);
        String idB = "Identificador de B";
        String chaveSessaoCifrada = cifraChaveSessao();
        saida.println(chaveSessaoCifrada + idB + na);
        System.out.println("Enviado para o servidor: " + chaveSessaoCifrada + idB + na);
        
        //Recebe a mensagem 2 do protocolo
        if(entrada.hasNextLine()) {

            System.out.println("Recebido do servidor: " + entrada.nextLine());

        }
        
        //Envia a mensagem 3 do protocolo
        saida.println("Mensagem 3");
        System.out.println("Enviado para o servidor: Mensagem 3");
        
        //entrada.close();
        
        
    }

    private static void enviaMsgServidor() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException, IllegalStateException, InvalidCipherTextException, NoSuchProviderException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        Scanner teclado = new Scanner(System.in);

        PrintStream saida = new PrintStream(socket.getOutputStream());
        
        //IvParameterSpec ivSpec = new IvParameterSpec(iv);

        while (teclado.hasNextLine()) {

            /*
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
            Key aesKey = sKenGen.generateKey();
            */
            
            GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
            String chaveHex = Hex.encodeHexString(chaveSessao.getEncoded());
            byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
            KeyParameter chave2 = new KeyParameter(chave);
            AEADParameters params = new AEADParameters(chave2, 64, iv);
            //System.out.println(new String(chave));
            //System.out.println(new String(iv));
            
            gcmChave.init(true, params);
            
            byte[] msgBytes = teclado.nextLine().getBytes();
            int outsize = gcmChave.getOutputSize(msgBytes.length);
            byte[] msgCifradaBytes = new byte[outsize];
            
            int lengthOutc = gcmChave.processBytes(msgBytes, 0, msgBytes.length, msgCifradaBytes, 0);
        
            gcmChave.doFinal(msgCifradaBytes, lengthOutc);
            
            String msgCifradaHex = Utils4.toHex(msgCifradaBytes);
            System.out.println("Mensagem cifrada enviada:" + msgCifradaHex);
            saida.println(msgCifradaHex);
            
            //teste
            /*GCMBlockCipher gcmChave2 = new GCMBlockCipher(new AESEngine());
            KeyParameter chave = new KeyParameter(chave);
            AEADParameters params2 = new AEADParameters(chave2, 64, iv);
            
            gcmChave.init(false, params);
            */
            /*
            //Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, (Key) chaveSessao, ivSpec);
            
            byte[] msgCifradaBytes = cipher.doFinal(teclado.nextLine().getBytes());
            String msgCifradaHex = Utils4.toHex(msgCifradaBytes);
            System.out.println("Mensagem cifrada enviada:" + msgCifradaHex);
            saida.println(msgCifradaHex);
*/

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
        
//        //teste
//        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
//        byte[] teste = org.apache.commons.codec.binary.Hex.decodeHex(chaveSessaoCifrada.toCharArray());
//        byte[] plainText = cipher.doFinal(teste);
//        SecretKey key = new SecretKeySpec(plainText, "AES");
//        if(key.equals(chaveSessao)){
//            System.out.println("Deu bom");
//            System.out.println(key.toString());
//        }else{
//            System.out.println("Deu ruim");
//            System.out.println(chaveSessao.toString());
//            System.out.println(key.toString());
//        }
//        //fim teste
        
        return chaveSessaoCifrada;
        
    }
    
}
