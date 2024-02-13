#include <stdio.h>
#include <stdlib.h>


#include "cbuf.h"


// initialize cbuf with data_len = len
int InitCBuf( struct _cbuf *cbuf, int len )
{
    if( !cbuf )
        return 0;
    
    cbuf->data = (uint8_t *)calloc( (unsigned long)len, sizeof(uint8_t) );
    if( !cbuf->data )
        len = 0;

    cbuf->data_len = len;
    cbuf->head = 0;
    cbuf->tail = 0;

    return len;
}


// free memory allocated by InitTSCBuf()
void FreeCBuf( struct _cbuf *cbuf )
{
    if( !cbuf )
        return;

    if( !cbuf->data )
        return;
    
    free( cbuf->data );

    return;
}


// returns # of bytes waiting in cbuf
int CheckCBuf( struct _cbuf *cbuf )
{
    int len;
    
    len = abs(cbuf->tail - cbuf->head);

    if( cbuf->tail < cbuf->head )
        len = cbuf->data_len - len;

    return len;
}


void AddByteToCBuf( struct _cbuf *cbuf, uint8_t data)
{
    cbuf->data[cbuf->tail++] = data;

    if( cbuf->tail >= cbuf->data_len )
        cbuf->tail=0;
        
    if( cbuf->tail == cbuf->head )
    {
        cbuf->head++;
    
        if( cbuf->head >= cbuf->data_len )
            cbuf->head=0;
    }
    
    return;
}


// add len bytes from data[] to cbuf
void AddDataToCBuf( struct _cbuf *cbuf, uint8_t *data, int len )
{
    int i;
    
    for( i=0; i<len; i++ )
        AddByteToCBuf( cbuf, data[i] );
    
    return;
}


// add len bytes from data[] to beginning of cbuf
int StuffDataInCBuf( struct _cbuf *cbuf, uint8_t *data, int len )
{
    int i;
    

    for( i=0; i<len; i++ )
    {
        cbuf->head--;
        if( cbuf->head < 0 )    // check for wrap-around
            cbuf->head = cbuf->data_len + cbuf->head;
        if( cbuf->tail == cbuf->head )
        {   // no room in buffer for this byte - it has been lost
            cbuf->head++;
            if( cbuf->head >= cbuf->data_len )
                cbuf->head = 0;
            return -1;
        }            
        cbuf->data[cbuf->head] = data[i];
    }

    
    return 0;
}


// returns -1 if no data available, or returns one byte from cbuf
int GetByteFromCBuf( struct _cbuf *cbuf )
{
  uint8_t data;


  if( cbuf->tail == cbuf->head )
    return -1;  // no data available

  data = cbuf->data[cbuf->head];
  cbuf->head++;
  if(cbuf->head >= cbuf->data_len)
    cbuf->head=0;
  
  return data;
}


// returns -1 if fewer than len bytes are available
// returns # of bytes read
int GetDataFromCBuf( struct _cbuf *cbuf, uint8_t *data, int len, int timeout )
{
    int nextbyte;
    int i;
    

    if( CheckCBuf( cbuf ) < len )
        return -1;
//TODO - keep trying to complete len bytes until timeout expires

    for( i=0; i<len; i++ )
    {
        nextbyte = GetByteFromCBuf( cbuf ); 
        if(nextbyte < 0 )
            break;
        data[i] = (uint8_t)nextbyte;
    }
    len = i;


    return len;
}
