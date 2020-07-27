package GraphGeneratorsDemo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Random;

import org.jgrapht.Graph;
import org.jgrapht.alg.util.AliasMethodSampler;
import org.jgrapht.alg.util.VertexDegreeComparator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.DepthFirstIterator;

import java.util.Set;


public class HelperClass {
	
	static final Random random = new Random();

	public static void sequenceGenerator(Graph<String, DefaultEdge> graph, int numberOfEdgesToAdd) throws FileNotFoundException {
        Set<String> vertexSet = graph.vertexSet();
        
        ArrayList<String> vertexList = new ArrayList<String>();
        vertexList.addAll(vertexSet);
        
        boolean condition = true;
        int counter = 0;
        double [] p= new double[1];
        
       // AliasMethodSampler aliasMethodSampler= new AliasMethodSampler(p);
        
        int range = vertexList.size() - 1;
        
        while(condition) {
        	int random1 = random.nextInt(range);
        	int random2 = random.nextInt(range);
        	if(random1 != random2) {
        		if(!graph.containsEdge(vertexList.get(random1), vertexList.get(random2))) {
        			
            		graph.addEdge(vertexList.get(random1), vertexList.get(random2));
    	        	counter++;
        			}
     
            	
            	if(counter == numberOfEdgesToAdd) {
            		condition = false; 
            	}
        	}
        }
        
        PrintStream o = new PrintStream(new File("barabasiAfterAddingEdges.txt"));
        System.setOut(o);
        
        
        for(int index = 0; index < vertexList.size(); index++) {
        	Set <DefaultEdge> la =  graph.edgesOf(vertexList.get(index));
        	for (DefaultEdge defaultEdge : la) {
        		System.out.println(defaultEdge.toString());
        	}
        
        
//        // Print out the graph to be sure it's really complete
//        Iterator<String> iter = new DepthFirstIterator<>(graph);
//        while (iter.hasNext()) {
//            String vertex = iter.next();
//            System.out.println(	
//                "Vertex " + vertex + " is connected to: "
//                    + graph.edgesOf(vertex).toString());
//        }
	}
	}}
