package sequence.generators.demo;

import java.io.BufferedReader;
import attacks.*;
import enterprise.sequence.generators.ScaleFreeNetworkSequenceGenerator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.generate.ScaleFreeGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.util.SupplierUtil;

import com.sun.javafx.image.impl.IntArgb;

public class ScaleFreeSequenceDemo {
	
//	public static int DEGREE_SUM;
//	public static List<Integer> DEGREES;
	public static int EDGE_COUNT = 0;
	public static void main(String[] args) throws IOException {
	    
	    ScaleFreeNetworkSequenceGenerator<String, DefaultEdge> generatorVertexes = new ScaleFreeNetworkSequenceGenerator<String, DefaultEdge>(20);
	    generatorVertexes.initialize(50);
//		
//		Set<String> vertexSet = freeScaleGraph.vertexSet();
//        ArrayList<String> vertexList = new ArrayList<String>();
//        vertexList.addAll(vertexSet);
//		
//        generatorVertexes.makeSnapshot(freeScaleGraph, vertexList, 5);
//        generatorVertexes.makeSnapshot(freeScaleGraph, vertexList, 50);
        
        //ScaleFreeNetworkSequenceGenerator<String, DefaultEdge> generatorEdges = new ScaleFreeNetworkSequenceGenerator<String, DefaultEdge>(20);
        //generatorEdges.initialize(1000);
        //ScaleFreeNetworkSequenceGenerator<String, DefaultEdge> generatorVertices= new ScaleFreeNetworkSequenceGenerator<String, DefaultEdge>();
        //generatorVertices.initialize(freeScaleGraph, 200);
        

//        Set<String> vertexSet = freeScaleGraph.vertexSet();
//        ArrayList<String> vertexList = new ArrayList<String>();
//        vertexList.addAll(vertexSet);
        
        
        
        //generatorEdges.makeSnapshot(0);
       
      
        
        //generatorEdges.makeSnapshot(0);
        //generatorEdges.makeSnapshot(freeScaleGraph, vertexList, 0);
	    generatorVertexes.makeSnapshot(50);
	}
}