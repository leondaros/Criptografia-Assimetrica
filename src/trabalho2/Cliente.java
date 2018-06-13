/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalho2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
    
    private static SecretKey chavesessao = null;
    private static byte[] iv = null;
    
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
        
        estabeleceConexao();
        
        enviaMsgServidor();
        
    }
    
    private static void estabeleceConexao() throws IOException, Exception {

        socket = new Socket("127.0.0.1", 12345);
        System.out.println("Conexão estabelecida com o servidor!");
        
        //Pergunta a senha para ser derivada a chave de sessão
        System.out.println("Insira a senha que será utilizada para derivar sua chave de sessão: ");
        Scanner scanner = new Scanner(System.in);
        chavesessao = generateDerivedKey(scanner.nextLine(), "881900f5d6e5cabca409675791601323", 10000);
        
        //Gera iv/nonce
        iv = geraIV();
        
        PrintStream saida = new PrintStream(socket.getOutputStream());
        saida.println("teste");
        System.out.println("Enviado para o servidor: teste");
        
        
        
        Scanner entrada = new Scanner(socket.getInputStream());
        
        if(entrada.hasNextLine()) {

            System.out.println("Recebido do servidor: " + entrada.nextLine());

        }
        
        saida.println("uhull");
        System.out.println("Enviado para o servidor: uhull");
        
        //entrada.close();
        
        
    }

    private static void enviaMsgServidor() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException, IllegalStateException, InvalidCipherTextException {

        int addProvider1 = Security.addProvider(new BouncyCastleProvider());
        
        Scanner teclado = new Scanner(System.in);

        PrintStream saida = new PrintStream(socket.getOutputStream());
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        while (teclado.hasNextLine()) {

            /*
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
            Key aesKey = sKenGen.generateKey();
            */
            GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
            String chaveHex = Hex.encodeHexString(chavesessao.getEncoded());
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
    
}
