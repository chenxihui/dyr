package sequence.generators.demo;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Set;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.generate.BarabasiAlbertForestGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.util.SupplierUtil;

import enterprise.sequence.generators.BarabasiAlbertForestSequenceGenerator;

public class BarabasiAlbertForestSequenceDemo {
	

	public static void main(String[] args) throws IOException {
	    
//	    BarabasiAlbertForestSequenceGenerator<String, DefaultEdge> generator = new BarabasiAlbertForestSequenceGenerator<String, DefaultEdge>(5,200);
//      generator.initialize(barabasiForestGraph, 0);
        
	    BarabasiAlbertForestSequenceGenerator<String, DefaultEdge> generator2 = new BarabasiAlbertForestSequenceGenerator<String, DefaultEdge>(2, 100, 15);
	    
	    //The parameter in this method is not used, because the generator immediately defines the graph. This method initializes the graph.
        generator2.initialize(10);
        
        //The parameter in this method is not used.
        generator2.makeSnapshot(15);
        
	}
}
