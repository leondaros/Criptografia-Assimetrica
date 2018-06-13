/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalho2;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author jan
 */
public class Servidor {

    private static Socket socket = null;
    
    private static Key chavePublica = null;
    private static Key chavePrivada = null;
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

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
    
    public static void estabeleceConexao() throws IOException{
        
        ServerSocket servidor = new ServerSocket(12345);
        
        System.out.println("Aguardando o cliente...");
        socket = servidor.accept();
        System.out.println("Conexão estabelecida com o cliente!");
        
        Scanner entrada = new Scanner(socket.getInputStream());
        
        if(entrada.hasNextLine()) {

            System.out.println("Recebido do cliente: " + entrada.nextLine());

        }
        
        PrintStream saida = new PrintStream(socket.getOutputStream());
        
        saida.println("funcionou?");
        System.out.println("Enviado para o cliente: funcionou?");
        
        if(entrada.hasNextLine()) {

            System.out.println("Recebido do cliente: " + entrada.nextLine());

        }
        
        //entrada.close();
        //saida.close();
        
    }

    private static void ouvirCliente() throws IOException {
        
        int addProvider1 = Security.addProvider(new BouncyCastleProvider());

        Scanner entrada = new Scanner(socket.getInputStream());

        while (entrada.hasNextLine()) {

            //Falta decifrar a mensagem cifrada do cliente
            System.out.println(entrada.nextLine());

        }
        
    }

    private static void geraChavePubPriv() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        
        KeyPair pair = generator.generateKeyPair();
        chavePublica = pair.getPublic();
        chavePrivada = pair.getPrivate();
        
    }
    
}
