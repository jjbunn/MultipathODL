package org.opendaylight.controller.multipath;

/*
* Copyright (c) 2013, California Institute of Technology
* ALL RIGHTS RESERVED.
* Based on Government Sponsored Research DE-SC0007346
* Author Michael Bredel <michael.bredel@cern.ch>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
* WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Neither the name of the California Institute of Technology
* (Caltech) nor the names of its contributors may be used to endorse
* or promote products derived from this software without specific prior
* written permission.
*/

import java.util.Set;

//import net.floodlightcontroller.core.module.IFloodlightService;
//import net.floodlightcontroller.routing.EndPoints;
//import net.floodlightcontroller.routing.Path;

import org.opendaylight.controller.sal.core.Node;

/**
*
* @author Michael Bredel <michael.bredel@cern.ch>
* @author Julian Bunn <Julian.Bunn@caltech.edu>
*
* (Ported to OpenDaylight from Floodlight.)
*/

public interface IPathCacheService {

/**
 * @param path
 * @return
 */
public ExtendedPath addPath(ExtendedPath path);

/**
 * @param pathSet
 * @return A Set of paths.
 */
public Set<ExtendedPath> addPaths(Set<ExtendedPath> pathSet);

/**
 *
 * @param pathid
 * @return
 */
public ExtendedPath removePath(int pathId);

/**
 *
 * @param srcNode
 * @param dstNode
 * @return
 */
public Set<ExtendedPath> removePath(Node srcNode, Node dstNode);

/**
 * Getter for a specific path in the path cache.
 *
 * @param pathId
 * @return
 */
public ExtendedPath getPath(int pathId);

/**
 * Getter for all paths stored in the path cache.
 *
 * @return
 */
public Set<ExtendedPath> getAllPaths();

/**
 * Getter for all paths stored in the path cache for a specific source-destination
 * pair.
 *
 * @param srcNode
 * @param dstNode
 * @return
 */
public Set<ExtendedPath> getAllPaths(Node srcNode, Node dstNode);

/**
 * Getter for all routeIds, i.e. source-destination pairs,
 * stored in the path cache.
 *
 * @return
 */
public Set<EndPoints> getAllEndPoints();

/**
 *
 * @param path
 * @return
 */
public boolean containsPath(ExtendedPath path);

/**
 *
 * @param pathId
 * @return
 */
public boolean containsPath(int pathId);

/**
 *
 * @param srcNode
 * @param dstNode
 * @return
 */
public boolean containsPath(Node srcNode, Node dstNode);

/**
 *
 * Generates a new unique path id.
 *
 * @return <b>int</b> A new unique path id.
 */
public int getNextPathId();

/**
 * Number of path sets (for routeIds) stored in the path cache.
 *
 * @return
 */
public int size();

/**
 * Returns true if this map contains no key-value mappings.
 *
 * @return <b>boolean</b> True if this map contains no key-value mappings.
 */
public boolean isEmpty();

/**
 * Clears the complete path cache data structure.
 */
public void clear();

}