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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
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
import static trabalho2.Cliente.geraIV;

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
    private static byte[] iv = null;
    //private static SecretKey chaveSessaoCliente = null;
    //private static IvParameterSpec ivSessaoCliente = null;
    private static byte[] ivSessaoCliente = null;
    
    private static byte[] chaveSessaoCliente = null;
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, NoSuchProviderException, InvalidAlgorithmParameterException, Exception {

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
    
    public static void estabeleceConexao() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, DecoderException, IllegalBlockSizeException, BadPaddingException, Exception{
        
        ServerSocket servidor = new ServerSocket(12345);
        
        System.out.println("Aguardando o cliente...");
        socket = servidor.accept();
        System.out.println("Conexão estabelecida com o cliente!");
        
        //Gera chave de sessao
        KeyGenerator sKenGen = KeyGenerator.getInstance("AES"); 
        chaveSessao = sKenGen.generateKey();
        
        //Gera iv/nonce
        iv = geraIV();
        
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
  
        String ivSessaoClienteString = null;
        String assinatura = null;
        //Recebe a mensagem 1 do protocolo
        if(entrada.hasNextLine()) {

            String mensagemRecebida = entrada.nextLine();
            //String chaveSessaoClienteCifrada = mensagemRecebida.substring(0, 512);
            String chaveSessaoClienteCifrada = mensagemRecebida.substring(0, 256);
            ivSessaoClienteString = mensagemRecebida.substring(274, 306);
            ivSessaoCliente = org.apache.commons.codec.binary.Hex.decodeHex(ivSessaoClienteString.toCharArray());
            decifraChaveSessaoCliente(chaveSessaoClienteCifrada);
            String idB = mensagemRecebida.substring(256, 274);
            assinatura = mensagemRecebida.substring(306, 562);
            System.out.println("Mensagem 1 recebida: " + mensagemRecebida);
            System.out.println("Chave de sessao Kab cifrada recebida: " + chaveSessaoClienteCifrada);
            System.out.println("Identificador de B recebido: " + idB);
            System.out.println("Nonce A recebido: " + ivSessaoClienteString);
            System.out.println("Assinatura dos parâmetros recebida: " + assinatura);
            //Verifica assinatura
            if(verificaAssinatura(mensagemRecebida.substring(0, 306), assinatura)){
                System.out.println("Autenticidade e Integridade foram garantidas!");
            }else{
                System.out.println("Validacao da assinatura indica problemas de Autenticidade e/ou Integridade");
            }
            System.out.println("");
            //System.out.println("Recebido do cliente: " + ivSessaoClienteString);

        }
        
        //Envia mensagem 2 do protocolo
        byte[] nbByte = iv;
        String nb = Utils4.toHex(nbByte);
        String idA = "Identificador de A";
        String chaveSessaoCifrada = cifraChaveSessao();
        assinatura = assinaParametros(chaveSessaoCifrada + idA + nb + ivSessaoClienteString);
        saida.println(chaveSessaoCifrada + idA + nb + ivSessaoClienteString + assinatura);
        System.out.println("Mensagem 2 do protocolo enviada ao cliente: " + chaveSessaoCifrada + idA + nb + ivSessaoClienteString + assinatura);
        System.out.println("Chave de sessao Kba cifrada enviada: " + chaveSessaoCifrada);
        System.out.println("Identificador de A enviado: " + idA);
        System.out.println("Nonce B enviado: " + nb);
        System.out.println("Nonce A enviado: " + ivSessaoClienteString);
        System.out.println("Assinatura dos parâmetros: " + assinatura);
        System.out.println("");
        
        
        //saida.println("Mensagem 2");
        //System.out.println("Enviado para o cliente: Mensagem 2");
        
        //Recebe a mensagem 3 do protocolo
        if(entrada.hasNextLine()) {

            String msgRecebida = entrada.nextLine();
            String idB = msgRecebida.substring(0, 18);
            nb = msgRecebida.substring(18, 50);
            assinatura = msgRecebida.substring(50, 306);
            
            System.out.println("Mensagem 3 recebida: " + msgRecebida);
            System.out.println("Identificador de B recebido: " + idB);
            System.out.println("Nonce B recebido: " + nb);
            System.out.println("Assinatura dos parâmetros recebida: " + assinatura);
            //Verifica assinatura
            if(verificaAssinatura(msgRecebida.substring(0, 50), assinatura)){
                System.out.println("Autenticidade e Integridade foram garantidas!");
            }else{
                System.out.println("Validacao da assinatura indica problemas de Autenticidade e/ou Integridade");
            }
            System.out.println("");
            

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
            KeyParameter chave2 = new KeyParameter(chaveSessaoCliente);
            AEADParameters params = new AEADParameters(chave2, 64, ivSessaoCliente);
            
            gcmChave.init(false, params);
            
            String msgRecebida = entrada.nextLine();
            byte[] msgBytes = org.apache.commons.codec.binary.Hex.decodeHex(msgRecebida.toCharArray());
            //byte[] msgBytes = entrada.nextLine().getBytes();
            int outsize = gcmChave.getOutputSize(msgBytes.length);
            byte[] msgDecifradaBytes = new byte[outsize];
            int offOut = gcmChave.processBytes(msgBytes, 0, msgBytes.length, msgDecifradaBytes, 0);
            
            gcmChave.doFinal(msgDecifradaBytes, offOut);
            System.out.println("Mensagem cifrada recebida do cliente: " + msgRecebida);
            System.out.println("Mensagem decifrada recebida do cliente: " + new String(msgDecifradaBytes));
            
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
        chaveSessaoCliente = chavePlanaByte;
        //chaveSessaoCliente = new SecretKeySpec(chavePlanaByte, "AES");
        
    }

    private static String cifraChaveSessao() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, chavePubCliente);

        byte[] cipherText = cipher.doFinal(chaveSessao.getEncoded());
        
        String chaveSessaoCifrada = Utils4.toHex(cipherText);
        
        return chaveSessaoCifrada;
        
    }
    
    private static String assinaParametros(String string) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest hash =  MessageDigest.getInstance("SHA256");
        hash.update(Utils4.toByteArray(string));
        
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
        cipher.init(Cipher.DECRYPT_MODE, chavePubCliente);
        
        byte[] assinaturaByte = org.apache.commons.codec.binary.Hex.decodeHex(assinatura.toCharArray());
        byte[] hashRecebidoByte = cipher.doFinal(assinaturaByte);
        String hashRecebido = Utils4.toHex(hashRecebidoByte);
        System.out.println("O hash recebido foi: " + hashRecebido);
        
        return hashParametrosCalculado.equals(hashRecebido);
        
    }
    
}
