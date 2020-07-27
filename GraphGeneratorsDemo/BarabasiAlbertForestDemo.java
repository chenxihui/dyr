package GraphGeneratorsDemo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.Random;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.generate.BarabasiAlbertForestGenerator;
import org.jgrapht.generate.BarabasiAlbertGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.traverse.DepthFirstIterator;
import org.jgrapht.util.SupplierUtil;

public class BarabasiAlbertForestDemo {
	static final int t=3;
	static final int n=1000;
	static final long seed= 100;
	
	 public static void main(String[] args) throws FileNotFoundException
	    {
	        // Create the VertexFactory so the generator can create vertices
	        Supplier<String> vSupplier = new Supplier<String>()
	        {
	            private int id = 0;

	            @Override
	            public String get()
	            {
	                return "v" + id++;
	            }
	        };

	        //@example:generate:begin
	        // Create the graph object
	   Graph<String, DefaultEdge> barabasiAlbertForestGraph =
	            new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
	        
//	        BarabasiAlbertGraphGenerator<String, DefaultEdge> BAGenerator =
// 	            new BarabasiAlbertGraphGenerator<>(m0, m, n, seed);
//     	BAGenerator.generateGraph(barabasiAlbertGraph);

	        // Create the CompleteGraphGenerator object
	   
	        		BarabasiAlbertForestGenerator<String, DefaultEdge> BAFGenerator =
		    	            new BarabasiAlbertForestGenerator<>(t, n, seed);
		        	BAFGenerator.generateGraph(barabasiAlbertForestGraph);
		        	
		        	PrintStream o = new PrintStream(new File("snapshot_BarabasiForest.txt"));
			        System.setOut(o);
			        // Print out the graph to be sure it's really complete
			        Iterator<String> iter = new DepthFirstIterator<>(barabasiAlbertForestGraph);
			        while (iter.hasNext()) {
			            String vertex = iter.next();
			            System.out.println(	
			                "Vertex " + vertex + " is connected to: "
			                    + barabasiAlbertForestGraph.edgesOf(vertex).toString());
			        }
			        
	        	}
	        	
	  
}
