package GraphGeneratorsDemo;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.generate.GnpRandomBipartiteGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.traverse.DepthFirstIterator;
import org.jgrapht.util.SupplierUtil;



public class GnpRandomBipartiteDemo {
	
	static final int n1=10;
	static final int n2=100;
	static final double p= 0.2;
	
	
public static void main(String []arg) throws FileNotFoundException {	
	   Supplier<String> vSupplier = new Supplier<String>()
       {
           private int id = 0;

           @Override
           public String get()
           {
               return "v" + id++;
           }
       };
       
      Graph<String, DefaultEdge> randomBipartiteGraph =
	            new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
      GnpRandomBipartiteGraphGenerator<String, DefaultEdge> GBPGenerator= new GnpRandomBipartiteGraphGenerator<String, DefaultEdge>(n1, n2, p);

      GBPGenerator.generateGraph(randomBipartiteGraph);
      
   	PrintStream o = new PrintStream(new File("snapshot_Bipartitep02.txt"));
    System.setOut(o);
    
      Iterator<String> iter = new DepthFirstIterator<>(randomBipartiteGraph);
      while (iter.hasNext()) {
          String vertex = iter.next();
          System.out.println(	
              "Vertex " + vertex + " is connected to: "
                  + randomBipartiteGraph.edgesOf(vertex).toString());
               }   
        }
   }



