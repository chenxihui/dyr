package attacks;

import java.util.Arrays;

public class Attacker {
	
	private int index ;
	
	private int degree ;
	
	private int cuDegree ;
	
	private int[] vertex ;
	
	public Attacker() {
	}
	
	public Attacker(int degree) {
		this.degree = degree ;
		this.cuDegree = degree ;
		vertex = new int[degree];
	}
	
	
	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public int getDegree() {
		return degree;
	}

	public void setDegree(int degree) {
		this.degree = degree;
	}
	
	public int getCuDegree() {
		return cuDegree;
	}

	public void setCuDegree(int cuDegree) {
		this.cuDegree = cuDegree;
	}

	public int[] getVertex() {
		return vertex;
	}

	public void setVertex(int[] vertex) {
		this.vertex = vertex;
	}

	@Override
	public String toString() {
		return "Aggressor [index=" + index + ", degree=" + degree
				+ ", cuDegree=" + cuDegree + ", vertex="
				+ Arrays.toString(vertex) + "]";
	}

}
