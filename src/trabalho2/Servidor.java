/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalho2;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

/**
 *
 * @author jan
 */
public class Servidor {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {

        ServerSocket servidor = new ServerSocket(12345);

        System.out.println("Porta 12345 aberta!");

        Socket cliente = servidor.accept();

        System.out.println("Nova conexão com o cliente "
                + cliente.getInetAddress().getHostAddress());

        Scanner entrada = new Scanner(cliente.getInputStream());

        while (entrada.hasNextLine()) {

            System.out.println(entrada.nextLine());

        }

        entrada.close();

        servidor.close();
        
    }
    
}
