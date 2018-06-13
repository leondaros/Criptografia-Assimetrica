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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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
public class Servidor {

    private static Socket socket = null;
    
    private static Key chavePublica = null;
    private static Key chavePrivada = null;
    
    private static Key chavePubCliente = null;
    
    private static SecretKey chaveSessao = null;
    private static SecretKey chaveSessaoCliente = null;
    //private static IvParameterSpec ivSessaoCliente = null;
    private static byte[] ivSessaoCliente = null;
    
    private static byte[] testeChave = null;
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, NoSuchProviderException, InvalidAlgorithmParameterException {

        /*ServerSocket servidor = new ServerSocket(12345);

        System.out.println("Porta 12345 aberta!");

        Socket cliente = servidor.accept();

        System.out.println("Nova conexão com o cliente "
                + cliente.getInetAddress().getHostAddress());

        Scanner entrada = new Scanner(cliente.getInputStream());

        while (entrada.hasNextLine()) {

            System.out.println(entrada.nextLine());

        }

        entrada.close();

        servidor.close();*/
        
        geraChavePubPriv();
        
        estabeleceConexao();
        
        ouvirCliente();
        
        
        
    }
    
    public static void estabeleceConexao() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException{
        
        ServerSocket servidor = new ServerSocket(12345);
        
        System.out.println("Aguardando o cliente...");
        socket = servidor.accept();
        System.out.println("Conexão estabelecida com o cliente!");
        
        //StringBuilder sb = new StringBuilder();
        
        //Recebe chave pública do cliente
        /*
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
            System.out.println("Chave publica do cliente recebida: " + sb.toString());

        }
        */
        //Recebe chave pública do cliente
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        if((chavePubCliente = (Key) ois.readObject()) != null){
            System.out.println("Chave publica do cliente recebida: ");
            System.out.println("");
            System.out.println(chavePubCliente.toString());
            System.out.println("");
        }
        
        //Envia chave pública para o cliente
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(chavePublica);
        System.out.println("Chave publica enviada para o cliente");
        System.out.println("");
        System.out.println(chavePublica.toString());
        System.out.println("");
        /*
        //Transforma chave pública em string
        String chavePubString = chavePublica.toString();
        
        //Envia chave pública para o cliente
        PrintStream saida = new PrintStream(socket.getOutputStream());
        saida.println(chavePubString);
        System.out.println("Chave publica enviada para o cliente: " + chavePubString);
        */
        
        Scanner entrada = new Scanner(socket.getInputStream());
        PrintStream saida = new PrintStream(socket.getOutputStream());
  
        //Recebe a mensagem 1 do protocolo
        if(entrada.hasNextLine()) {

            String mensagemRecebida = entrada.nextLine();
            String chaveSessaoClienteCifrada = mensagemRecebida.substring(0, 512);
            String ivSessaoClienteString = mensagemRecebida.substring(530, 562);
            ivSessaoCliente = org.apache.commons.codec.binary.Hex.decodeHex(ivSessaoClienteString.toCharArray());
            decifraChaveSessaoCliente(chaveSessaoClienteCifrada);
            //System.out.println("Recebido do cliente: " + chaveSessaoClienteCifrada);
            //System.out.println("Recebido do cliente: " + ivSessaoClienteString);

        }
        
        //Envia mensagem 2 do protocolo
        saida.println("Mensagem 2");
        System.out.println("Enviado para o cliente: Mensagem 2");
        
        //Recebe a mensagem 3 do protocolo
        if(entrada.hasNextLine()) {

            System.out.println("Recebido do cliente: " + entrada.nextLine());

        }
        
        //entrada.close();
        //saida.close();
        
    }

    private static void ouvirCliente() throws IOException, DecoderException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        int addProvider1 = Security.addProvider(new BouncyCastleProvider());

        Scanner entrada = new Scanner(socket.getInputStream());

        while (entrada.hasNextLine()) {

            //Falta decifrar a mensagem cifrada do cliente
            GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
            KeyParameter chave2 = new KeyParameter(testeChave);
            AEADParameters params = new AEADParameters(chave2, 64, ivSessaoCliente);
            
            gcmChave.init(false, params);
            
            
            byte[] msgBytes = org.apache.commons.codec.binary.Hex.decodeHex(entrada.nextLine().toCharArray());
            //byte[] msgBytes = entrada.nextLine().getBytes();
            int outsize = gcmChave.getOutputSize(msgBytes.length);
            byte[] msgDecifradaBytes = new byte[outsize];
            int offOut = gcmChave.processBytes(msgBytes, 0, msgBytes.length, msgDecifradaBytes, 0);
            
            gcmChave.doFinal(msgDecifradaBytes, offOut);
            System.out.println(new String(msgDecifradaBytes));
            
            /*
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, chaveSessaoCliente, ivSessaoCliente);
            
            byte[] msgCifradaBytes = Hex.decodeHex(entrada.nextLine().toCharArray());
            byte[] msgDecifradaBytes = cipher.doFinal(msgCifradaBytes);
            String msgDecifrada = new String(msgDecifradaBytes);
            
            System.out.println(msgDecifrada);
            */
            //System.out.println(new String(testeChave));
            //System.out.println(new String(ivSessaoCliente));
            //System.out.println(entrada.nextLine());

        }
        
    }

    private static void geraChavePubPriv() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        
        KeyPair pair = generator.generateKeyPair();
        chavePublica = pair.getPublic();
        chavePrivada = pair.getPrivate();
        
    }

    private static void decifraChaveSessaoCliente(String chaveSessaoClienteCifrada) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException {

        int addProvider1 = Security.addProvider(new BouncyCastleProvider());
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        
        byte[] chaveCifradaByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveSessaoClienteCifrada.toCharArray());
        byte[] chavePlanaByte = cipher.doFinal(chaveCifradaByte);
        //teste
        testeChave = chavePlanaByte;
        //chaveSessaoCliente = new SecretKeySpec(chavePlanaByte, "AES");
        
    }
    
}
