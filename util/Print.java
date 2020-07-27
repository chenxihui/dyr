package util;

import java.util.Set;

import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

public class Print {

	public static void printList(Set<String> base) {
		System.out.println(base.toString());
	}

	public static void printGraph(SimpleGraph<String, DefaultEdge> graph) {
		System.out.println(graph.toString());
	}

	public static void print(String s) {
		System.out.println(s);
	}

	
}
